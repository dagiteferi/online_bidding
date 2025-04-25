<?php
/**
 * Admin Dashboard
 * 
 * This file handles the main administrative interface for the online bidding system.
 * It provides functionality for managing items for sale, buy requests, and system settings.
 * 
 * Main Features:
 * 1. Item Management
 * 2. Buy Request Management
 * 3. Offer Management
 * 4. Item Type Management
 * 
 * Security Features:
 * - Session validation
 * - Admin role verification
 * - Input sanitization
 * - Error handling and logging
 * - CSRF protection
 * - SQL injection prevention
 */

session_start();
require_once '../config/db_connect.php';

// CSRF Token Generation
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Admin Authentication Check
if (!isset($_SESSION['user_id']) || !isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
    header("Location: login.php");
    exit();
}

// Validate user_id in database
try {
    $stmt = $pdo->prepare("SELECT id FROM users WHERE id = :user_id AND is_admin = 1");
    $stmt->execute([':user_id' => $_SESSION['user_id']]);
    if (!$stmt->fetch()) {
        session_destroy();
        header("Location: login.php?error=invalid_user");
        exit();
    }
} catch (PDOException $e) {
    error_log("Error validating user_id: " . $e->getMessage());
    session_destroy();
    header("Location: login.php?error=database_error");
    exit();
}

$admin_name = "Admin"; // Hardcoded as per login.php

// Update expired items and buy requests
try {
    $current_time = date('Y-m-d H:i:s');
    $stmt = $pdo->prepare("UPDATE items SET status = 'closed' WHERE close_time IS NOT NULL AND close_time <= :current_time AND status = 'open'");
    $stmt->execute([':current_time' => $current_time]);
    
    $stmt = $pdo->prepare("UPDATE buy_requests SET status = 'closed' WHERE close_time IS NOT NULL AND close_time <= :current_time AND status = 'open'");
    $stmt->execute([':current_time' => $current_time]);
} catch (PDOException $e) {
    error_log("Error updating expired close times: " . $e->getMessage());
}

// Helper function for input sanitization
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// Handle Post Sell Item
if (isset($_GET['action']) && $_GET['action'] == 'post_sell') {
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        // CSRF validation
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            $error = "Invalid CSRF token.";
            error_log("CSRF validation failed for post_sell");
        } else {
            try {
                $supplier_name = sanitizeInput($_POST['supplier_name']);
                $item_name = sanitizeInput($_POST['item_name']);
                $item_type = sanitizeInput($_POST['item_type']);
                $description = sanitizeInput($_POST['description']);
                $price = floatval($_POST['price']);
                $quantity = intval($_POST['quantity']);
                $close_time = !empty($_POST['close_time']) ? date('Y-m-d H:i:s', strtotime($_POST['close_time'])) : null;
                $user_id = $_SESSION['user_id'];
                $image_path = null;

                if (empty($supplier_name) || empty($item_name) || empty($item_type) || empty($description) || $price <= 0 || $quantity <= 0) {
                    $error = "All fields are required, and price/quantity must be positive.";
                    error_log("Validation failed: supplier_name='$supplier_name', item_name='$item_name', item_type='$item_type', description='$description', price=$price, quantity=$quantity");
                } elseif ($close_time && $close_time <= date('Y-m-d H:i:s')) {
                    $error = "Close time must be in the future.";
                    error_log("Close time validation failed: close_time='$close_time'");
                } else {
                    if (isset($_FILES['image']) && $_FILES['image']['error'] == UPLOAD_ERR_OK) {
                        $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
                        $max_size = 5 * 1024 * 1024;
                        $upload_dir = dirname(__DIR__) . '/uploads/';
                        $file_name = uniqid('item_') . '_' . basename($_FILES['image']['name']);
                        $file_path = $upload_dir . $file_name;
                        $file_type = mime_content_type($_FILES['image']['tmp_name']);

                        if (!is_dir($upload_dir) && !mkdir($upload_dir, 0775, true)) {
                            $error = "Failed to create uploads directory.";
                            error_log("Failed to create uploads directory: $upload_dir");
                        }

                        if (!isset($error) && !in_array($file_type, $allowed_types)) {
                            $error = "Only JPEG, PNG, and GIF images are allowed.";
                            error_log("Invalid image type: $file_type");
                        } elseif (!isset($error) && $_FILES['image']['size'] > $max_size) {
                            $error = "Image size must be less than 5MB.";
                            error_log("Image size too large: {$_FILES['image']['size']} bytes");
                        } elseif (!isset($error) && !move_uploaded_file($_FILES['image']['tmp_name'], $file_path)) {
                            $error = "Failed to upload image.";
                            error_log("Failed to upload image to $file_path");
                        } else {
                            $image_path = 'uploads/' . $file_name;
                        }
                    }

                    if (!isset($error)) {
                        $stmt = $pdo->prepare("INSERT INTO items (posted_by, supplier_name, item_name, item_type, description, price, quantity, status, image, close_time, created_at) VALUES (:posted_by, :supplier_name, :item_name, :item_type, :description, :price, :quantity, 'open', :image, :close_time, NOW())");
                        $result = $stmt->execute([
                            ':posted_by' => $user_id,
                            ':supplier_name' => $supplier_name,
                            ':item_name' => $item_name,
                            ':item_type' => $item_type,
                            ':description' => $description,
                            ':price' => $price,
                            ':quantity' => $quantity,
                            ':image' => $image_path,
                            ':close_time' => $close_time
                        ]);
                        if ($result) {
                            $success = "Item posted for sale successfully!";
                            header("Location: admin_dashboard.php?action=items_for_sell");
                            exit();
                        }
                    }
                }
            } catch (PDOException $e) {
                $error = "Error posting item: " . $e->getMessage();
                error_log("Error posting item: " . $e->getMessage());
            }
        }
    }
}

// Handle Post Buy Item
if (isset($_GET['action']) && $_GET['action'] == 'post_buy') {
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            $error = "Invalid CSRF token.";
            error_log("CSRF validation failed for post_buy");
        } else {
            try {
                $item_name = sanitizeInput($_POST['item_name']);
                $item_type = sanitizeInput($_POST['item_type']);
                $description = sanitizeInput($_POST['description']);
                $max_price = floatval($_POST['max_price']);
                $quantity = intval($_POST['quantity']);
                $close_time = !empty($_POST['close_time']) ? date('Y-m-d H:i:s', strtotime($_POST['close_time'])) : null;
                $user_id = $_SESSION['user_id'];
                $image_path = null;

                if (empty($item_name) || empty($item_type) || empty($description) || $max_price <= 0 || $quantity <= 0) {
                    $error = "All fields are required, and max price/quantity must be positive.";
                } elseif ($close_time && $close_time <= date('Y-m-d H:i:s')) {
                    $error = "Close time must be in the future.";
                } else {
                    if (isset($_FILES['image']) && $_FILES['image']['error'] == UPLOAD_ERR_OK) {
                        $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
                        $max_size = 5 * 1024 * 1024;
                        $upload_dir = dirname(__DIR__) . '/uploads/';
                        $file_name = uniqid('buy_request_') . '_' . basename($_FILES['image']['name']);
                        $file_path = $upload_dir . $file_name;
                        $file_type = mime_content_type($_FILES['image']['tmp_name']);

                        if (!is_dir($upload_dir) && !mkdir($upload_dir, 0775, true)) {
                            $error = "Failed to create uploads directory.";
                        }

                        if (!isset($error) && !in_array($file_type, $allowed_types)) {
                            $error = "Only JPEG, PNG, and GIF images are allowed.";
                        } elseif (!isset($error) && $_FILES['image']['size'] > $max_size) {
                            $error = "Image size must be less than 5MB.";
                        } elseif (!isset($error) && !move_uploaded_file($_FILES['image']['tmp_name'], $file_path)) {
                            $error = "Failed to upload image.";
                        } else {
                            $image_path = 'uploads/' . $file_name;
                        }
                    }

                    if (!isset($error)) {
                        $stmt = $pdo->prepare("INSERT INTO buy_requests (user_id, item_name, item_type, description, max_price, quantity, status, image, close_time, created_at) VALUES (:user_id, :item_name, :item_type, :description, :max_price, :quantity, 'open', :image, :close_time, NOW())");
                        $stmt->execute([
                            ':user_id' => $user_id,
                            ':item_name' => $item_name,
                            ':item_type' => $item_type,
                            ':description' => $description,
                            ':max_price' => $max_price,
                            ':quantity' => $quantity,
                            ':image' => $image_path,
                            ':close_time' => $close_time
                        ]);
                        $success = "Buy request posted successfully!";
                        header("Location: admin_dashboard.php?action=buy_requests");
                        exit();
                    }
                }
            } catch (PDOException $e) {
                $error = "Error posting buy request: " . $e->getMessage();
            }
        }
    }
}

// Handle Item Type Management
if (isset($_GET['action']) && $_GET['action'] == 'add_item_type') {
    try {
        // Fetch existing item types
        $stmt = $pdo->query("SELECT type_name FROM item_types");
        $item_types = $stmt->fetchAll(PDO::FETCH_COLUMN);

        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
                $error = "Invalid CSRF token.";
            } else {
                $type_name = trim(sanitizeInput($_POST['type_name']));
                
                if (empty($type_name)) {
                    $error = "Type name is required.";
                } elseif (strlen($type_name) > 50) {
                    $error = "Type name must be less than 50 characters.";
                } elseif (in_array($type_name, $item_types)) {
                    $error = "Item type already exists.";
                } else {
                    $stmt = $pdo->prepare("INSERT INTO item_types (type_name) VALUES (:type_name)");
                    $stmt->execute([':type_name' => $type_name]);
                    $success = "Item type added successfully!";
                    header("Location: admin_dashboard.php?action=add_item_type");
                    exit();
                }
            }
        }
    } catch (PDOException $e) {
        error_log("Error managing item types: " . $e->getMessage());
        $error = "An error occurred while managing item types. Please try again.";
    }
}

// Handle Delete Item Type
if (isset($_GET['action']) && $_GET['action'] == 'delete_item_type' && isset($_GET['type_name'])) {
    try {
        $type_name = sanitizeInput($_GET['type_name']);
        
        // Check if type is in use
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM items WHERE item_type = :type_name UNION SELECT COUNT(*) FROM buy_requests WHERE item_type = :type_name");
        $stmt->execute([':type_name' => $type_name]);
        $counts = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        if (array_sum($counts) > 0) {
            $error = "Cannot delete item type - it is currently in use.";
        } else {
            $stmt = $pdo->prepare("DELETE FROM item_types WHERE type_name = :type_name");
            $stmt->execute([':type_name' => $type_name]);
            if ($stmt->rowCount() > 0) {
                $success = "Item type deleted successfully!";
            } else {
                $error = "Item type not found.";
            }
        }
        header("Location: admin_dashboard.php?action=add_item_type");
        exit();
    } catch (PDOException $e) {
        error_log("Error deleting item type: " . $e->getMessage());
        $error = "An error occurred while deleting the item type. Please try again.";
    }
}

// Handle Edit Item
if (isset($_GET['action']) && $_GET['action'] == 'edit_item' && isset($_GET['item_id'])) {
    $item_id = intval($_GET['item_id']);
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            $error = "Invalid CSRF token.";
        } else {
            try {
                $supplier_name = sanitizeInput($_POST['supplier_name']);
                $item_name = sanitizeInput($_POST['item_name']);
                $item_type = sanitizeInput($_POST['item_type']);
                $description = sanitizeInput($_POST['description']);
                $price = floatval($_POST['price']);
                $quantity = intval($_POST['quantity']);
                $close_time = !empty($_POST['close_time']) ? date('Y-m-d H:i:s', strtotime($_POST['close_time'])) : null;
                $image_path = $_POST['existing_image'] ?? null;

                if (empty($supplier_name) || empty($item_name) || empty($item_type) || empty($description) || $price <= 0 || $quantity < 0) {
                    $error = "All fields are required, and price must be positive, quantity must be non-negative.";
                } elseif ($close_time && $close_time <= date('Y-m-d H:i:s')) {
                    $error = "Close time must be in the future.";
                } else {
                    if (isset($_FILES['image']) && $_FILES['image']['error'] == UPLOAD_ERR_OK) {
                        $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
                        $max_size = 5 * 1024 * 1024;
                        $upload_dir = dirname(__DIR__) . '/uploads/';
                        $file_name = uniqid('item_') . '_' . basename($_FILES['image']['name']);
                        $file_path = $upload_dir . $file_name;
                        $file_type = mime_content_type($_FILES['image']['tmp_name']);

                        if (!is_dir($upload_dir) && !mkdir($upload_dir, 0775, true)) {
                            $error = "Failed to create uploads directory.";
                        }

                        if (!isset($error) && !in_array($file_type, $allowed_types)) {
                            $error = "Only JPEG, PNG, and GIF images are allowed.";
                        } elseif (!isset($error) && $_FILES['image']['size'] > $max_size) {
                            $error = "Image size must be less than 5MB.";
                        } elseif (!isset($error) && !move_uploaded_file($_FILES['image']['tmp_name'], $file_path)) {
                            $error = "Failed to upload image.";
                        } else {
                            $image_path = 'uploads/' . $file_name;
                            if (!empty($_POST['existing_image'])) {
                                $old_image = dirname(__DIR__) . '/' . $_POST['existing_image'];
                                if (file_exists($old_image)) {
                                    unlink($old_image);
                                }
                            }
                        }
                    }

                    if (!isset($error)) {
                        $stmt = $pdo->prepare("UPDATE items SET supplier_name = :supplier_name, item_name = :item_name, item_type = :item_type, description = :description, price = :price, quantity = :quantity, image = :image, close_time = :close_time WHERE id = :item_id AND posted_by = :posted_by");
                        $stmt->execute([
                            ':supplier_name' => $supplier_name,
                            ':item_name' => $item_name,
                            ':item_type' => $item_type,
                            ':description' => $description,
                            ':price' => $price,
                            ':quantity' => $quantity,
                            ':image' => $image_path,
                            ':close_time' => $close_time,
                            ':item_id' => $item_id,
                            ':posted_by' => $_SESSION['user_id']
                        ]);
                        if ($stmt->rowCount() > 0) {
                            $success = "Item updated successfully!";
                        } else {
                            $error = "Item not found or you don't have permission to edit it.";
                        }
                        header("Location: admin_dashboard.php?action=items_for_sell");
                        exit();
                    }
                }
            } catch (PDOException $e) {
                $error = "Error updating item: " . $e->getMessage();
            }
        }
    } else {
        try {
            $stmt = $pdo->prepare("SELECT * FROM items WHERE id = :item_id AND posted_by = :posted_by");
            $stmt->execute([
                ':item_id' => $item_id,
                ':posted_by' => $_SESSION['user_id']
            ]);
            $item_to_edit = $stmt->fetch();
            if (!$item_to_edit) {
                $error = "Item not found or you don't have permission to edit it.";
            }
        } catch (PDOException $e) {
            $error = "Error fetching item: " . $e->getMessage();
        }
    }
}

// Handle Close Item
if (isset($_GET['action']) && $_GET['action'] == 'close_item' && isset($_GET['item_id'])) {
    $item_id = intval($_GET['item_id']);
    try {
        $stmt = $pdo->prepare("UPDATE items SET status = 'closed' WHERE id = :item_id AND posted_by = :posted_by");
        $stmt->execute([
            ':item_id' => $item_id,
            ':posted_by' => $_SESSION['user_id']
        ]);
        if ($stmt->rowCount() > 0) {
            $success = "Item marked as closed successfully!";
        } else {
            $error = "Item not found or you don't have permission to close it.";
        }
        header("Location: admin_dashboard.php?action=items_for_sell");
        exit();
    } catch (PDOException $e) {
        $error = "Error closing item: " . $e->getMessage();
    }
}

// Handle Reopen Item
if (isset($_GET['action']) && $_GET['action'] == 'reopen_item' && isset($_GET['item_id'])) {
    $item_id = intval($_GET['item_id']);
    try {
        $stmt = $pdo->prepare("UPDATE items SET status = 'open' WHERE id = :item_id AND posted_by = :posted_by");
        $stmt->execute([
            ':item_id' => $item_id,
            ':posted_by' => $_SESSION['user_id']
        ]);
        if ($stmt->rowCount() > 0) {
            $success = "Item reopened successfully!";
        } else {
            $error = "Item not found or you don't have permission to reopen it.";
        }
        header("Location: admin_dashboard.php?action=items_for_sell");
        exit();
    } catch (PDOException $e) {
        $error = "Error reopening item: " . $e->getMessage();
    }
}

// Handle Delete Item
if (isset($_GET['action']) && $_GET['action'] == 'delete_item' && isset($_GET['item_id'])) {
    $item_id = intval($_GET['item_id']);
    try {
        $pdo->beginTransaction();
        $stmt = $pdo->prepare("SELECT image FROM items WHERE id = :item_id AND posted_by = :posted_by");
        $stmt->execute([
            ':item_id' => $item_id,
            ':posted_by' => $_SESSION['user_id']
        ]);
        $item = $stmt->fetch();

        if ($item) {
            $stmt = $pdo->prepare("DELETE t FROM transactions t JOIN offers o ON t.offer_id = o.id WHERE o.item_id = :item_id");
            $stmt->execute([':item_id' => $item_id]);

            $stmt = $pdo->prepare("DELETE FROM offers WHERE item_id = :item_id");
            $stmt->execute([':item_id' => $item_id]);

            if (!empty($item['image'])) {
                $image_path = dirname(__DIR__) . '/' . $item['image'];
                if (file_exists($image_path)) {
                    unlink($image_path);
                }
            }

            $stmt = $pdo->prepare("DELETE FROM items WHERE id = :item_id AND posted_by = :posted_by");
            $stmt->execute([
                ':item_id' => $item_id,
                ':posted_by' => $_SESSION['user_id']
            ]);
            if ($stmt->rowCount() > 0) {
                $success = "Item, related offers, and transactions deleted successfully!";
            } else {
                $error = "Item not found or you don't have permission to delete it.";
            }
            $pdo->commit();
        } else {
            $error = "Item not found or you don't have permission to delete it.";
            $pdo->rollBack();
        }
        header("Location: admin_dashboard.php?action=items_for_sell");
        exit();
    } catch (PDOException $e) {
        $pdo->rollBack();
        $error = "Error deleting item: " . $e->getMessage();
    }
}

// Handle Cancel Buy Request
if (isset($_GET['action']) && $_GET['action'] == 'cancel_buy_request' && isset($_GET['request_id'])) {
    $request_id = intval($_GET['request_id']);
    try {
        $stmt = $pdo->prepare("UPDATE buy_requests SET status = 'closed' WHERE id = :request_id AND user_id = :user_id");
        $stmt->execute([
            ':request_id' => $request_id,
            ':user_id' => $_SESSION['user_id']
        ]);
        if ($stmt->rowCount() > 0) {
            $success = "Buy request canceled successfully!";
        } else {
            $error = "Buy request not found or you don't have permission to cancel it.";
        }
        header("Location: admin_dashboard.php?action=buy_requests");
        exit();
    } catch (PDOException $e) {
        $error = "Error canceling buy request: " . $e->getMessage();
    }
}

// Handle Reopen Buy Request
if (isset($_GET['action']) && $_GET['action'] == 'reopen_buy_request' && isset($_GET['request_id'])) {
    $request_id = intval($_GET['request_id']);
    try {
        $stmt = $pdo->prepare("UPDATE buy_requests SET status = 'open' WHERE id = :request_id AND user_id = :user_id");
        $stmt->execute([
            ':request_id' => $request_id,
            ':user_id' => $_SESSION['user_id']
        ]);
        if ($stmt->rowCount() > 0) {
            $success = "Buy request reopened successfully!";
        } else {
            $error = "Buy request not found or you don't have permission to reopen it.";
        }
        header("Location: admin_dashboard.php?action=buy_requests");
        exit();
    } catch (PDOException $e) {
        $error = "Error reopening buy request: " . $e->getMessage();
    }
}

// Handle Delete Buy Request
if (isset($_GET['action']) && $_GET['action'] == 'delete_buy_request' && isset($_GET['request_id'])) {
    $request_id = intval($_GET['request_id']);
    try {
        $pdo->beginTransaction();
        $stmt = $pdo->prepare("SELECT image FROM buy_requests WHERE id = :request_id AND user_id = :user_id");
        $stmt->execute([
            ':request_id' => $request_id,
            ':user_id' => $_SESSION['user_id']
        ]);
        $request = $stmt->fetch();

        if ($request) {
            $stmt = $pdo->prepare("DELETE t FROM transactions t JOIN offers o ON t.offer_id = o.id WHERE o.request_id = :request_id");
            $stmt->execute([':request_id' => $request_id]);

            $stmt = $pdo->prepare("DELETE FROM offers WHERE request_id = :request_id");
            $stmt->execute([':request_id' => $request_id]);

            if (!empty($request['image'])) {
                $image_path = dirname(__DIR__) . '/' . $request['image'];
                if (file_exists($image_path)) {
                    unlink($image_path);
                }
            }

            $stmt = $pdo->prepare("DELETE FROM buy_requests WHERE id = :request_id AND user_id = :user_id");
            $stmt->execute([
                ':request_id' => $request_id,
                ':user_id' => $_SESSION['user_id']
            ]);
            if ($stmt->rowCount() > 0) {
                $success = "Buy request, related offers, and transactions deleted successfully!";
            } else {
                $error = "Buy request not found or you don't have permission to delete it.";
            }
            $pdo->commit();
        } else {
            $error = "Buy request not found or you don't have permission to delete it.";
            $pdo->rollBack();
        }
        header("Location: admin_dashboard.php?action=buy_requests");
        exit();
    } catch (PDOException $e) {
        $pdo->rollBack();
        $error = "Error deleting buy request: " . $e->getMessage();
    }
}

// Handle View Offers for Buy Request
if (isset($_GET['action']) && $_GET['action'] == 'view_offers' && isset($_GET['request_id'])) {
    $request_id = intval($_GET['request_id']);
    try {
        $stmt = $pdo->prepare("SELECT o.*, u.username, br.item_name 
            FROM offers o 
            JOIN users u ON o.user_id = u.id 
            JOIN buy_requests br ON o.request_id = br.id 
            WHERE o.request_id = :request_id AND o.status = 'pending' AND br.user_id = :user_id");
        $stmt->execute([
            ':request_id' => $request_id,
            ':user_id' => $_SESSION['user_id']
        ]);
        $buy_request_offers = $stmt->fetchAll();
    } catch (PDOException $e) {
        $error = "Error fetching offers: " . $e->getMessage();
    }
}

// Handle Close Offer
if (isset($_GET['action']) && $_GET['action'] == 'close_offer' && isset($_GET['offer_id'])) {
    $offer_id = intval($_GET['offer_id']);
    try {
        $stmt = $pdo->prepare("UPDATE offers SET status = 'closed' WHERE id = :offer_id");
        $stmt->execute([':offer_id' => $offer_id]);
        $success = "Offer closed successfully!";
        header("Location: admin_dashboard.php?action=offers");
        exit();
    } catch (PDOException $e) {
        $error = "Error closing offer: " . $e->getMessage();
    }
}

// Handle Delete Offer
if (isset($_GET['action']) && $_GET['action'] == 'delete_offer' && isset($_GET['offer_id'])) {
    $offer_id = intval($_GET['offer_id']);
    try {
        $pdo->beginTransaction();
        $stmt = $pdo->prepare("DELETE FROM transactions WHERE offer_id = :offer_id");
        $stmt->execute([':offer_id' => $offer_id]);

        $stmt = $pdo->prepare("DELETE FROM offers WHERE id = :offer_id");
        $stmt->execute([':offer_id' => $offer_id]);
        if ($stmt->rowCount() > 0) {
            $success = "Offer and related transactions deleted successfully!";
        } else {
            $error = "Offer not found.";
        }
        $pdo->commit();
        header("Location: admin_dashboard.php?action=offers");
        exit();
    } catch (PDOException $e) {
        $pdo->rollBack();
        $error = "Error deleting offer: " . $e->getMessage();
    }
}

// Handle Offer Actions
if (isset($_GET['action']) && $_GET['action'] == 'offer_action' && isset($_GET['offer_id']) && isset($_GET['type'])) {
    $offer_id = intval($_GET['offer_id']);
    $action_type = sanitizeInput($_GET['type']);

    try {
        $stmt = $pdo->prepare("SELECT o.offered_price, o.quantity, o.item_id, o.request_id, o.user_id AS buyer_id, i.posted_by AS seller_id, i.quantity AS available_quantity 
            FROM offers o 
            LEFT JOIN items i ON o.item_id = i.id 
            WHERE o.id = :offer_id");
        $stmt->execute([':offer_id' => $offer_id]);
        $offer = $stmt->fetch();

        if (!$offer) {
            $error = "Offer not found.";
        } else {
            if ($action_type == 'accept') {
                $stmt = $pdo->prepare("UPDATE offers SET status = 'accepted' WHERE id = :offer_id");
                $stmt->execute([':offer_id' => $offer_id]);

                if ($offer['item_id']) {
                    $stmt = $pdo->prepare("INSERT INTO transactions (item_id, offer_id, buyer_or_seller_id, final_price, quantity, created_at) 
                        VALUES (:item_id, :offer_id, :buyer_id, :final_price, :quantity, NOW())");
                    $stmt->execute([
                        ':item_id' => $offer['item_id'],
                        ':offer_id' => $offer_id,
                        ':buyer_id' => $offer['buyer_id'],
                        ':final_price' => $offer['offered_price'],
                        ':quantity' => $offer['quantity']
                    ]);

                    $new_quantity = $offer['available_quantity'] - $offer['quantity'];
                    $stmt = $pdo->prepare("UPDATE items SET quantity = :new_quantity WHERE id = :item_id");
                    $stmt->execute([
                        ':new_quantity' => $new_quantity,
                        ':item_id' => $offer['item_id']
                    ]);

                    if ($new_quantity <= 0) {
                        $stmt = $pdo->prepare("UPDATE items SET status = 'closed' WHERE id = :item_id");
                        $stmt->execute([':item_id' => $offer['item_id']]);
                    }
                } elseif ($offer['request_id']) {
                    $stmt = $pdo->prepare("SELECT quantity FROM buy_requests WHERE id = :request_id");
                    $stmt->execute([':request_id' => $offer['request_id']]);
                    $request = $stmt->fetch();
                    $requested_quantity = $request['quantity'];

                    $stmt = $pdo->prepare("INSERT INTO transactions (request_id, offer_id, buyer_or_seller_id, final_price, quantity, created_at) 
                        VALUES (:request_id, :offer_id, :buyer_id, :final_price, :quantity, NOW())");
                    $stmt->execute([
                        ':request_id' => $offer['request_id'],
                        ':offer_id' => $offer_id,
                        ':buyer_id' => $offer['buyer_id'],
                        ':final_price' => $offer['offered_price'],
                        ':quantity' => $offer['quantity']
                    ]);

                    $new_quantity = $requested_quantity - $offer['quantity'];
                    $stmt = $pdo->prepare("UPDATE buy_requests SET quantity = :new_quantity WHERE id = :request_id");
                    $stmt->execute([
                        ':new_quantity' => $new_quantity,
                        ':request_id' => $offer['request_id']
                    ]);

                    if ($new_quantity <= 0) {
                        $stmt = $pdo->prepare("UPDATE buy_requests SET status = 'closed' WHERE id = :request_id");
                        $stmt->execute([':request_id' => $offer['request_id']]);
                    }
                }
                $success = "Offer accepted successfully!";
            } elseif ($action_type == 'reject') {
                $stmt = $pdo->prepare("UPDATE offers SET status = 'rejected' WHERE id = :offer_id");
                $stmt->execute([':offer_id' => $offer_id]);
                $success = "Offer rejected successfully!";
            } else {
                $error = "Invalid action type.";
            }
        }
    } catch (PDOException $e) {
        $error = "Error processing offer: " . $e->getMessage();
    }
    header("Location: admin_dashboard.php?action=offers");
    exit();
}

// Handle Report Generation and Export
if (isset($_GET['action']) && $_GET['action'] == 'report' && isset($_GET['generate_report'])) {
    $start_date = sanitizeInput($_POST['start_date'] ?? '');
    $end_date = sanitizeInput($_POST['end_date'] ?? '');
    $transaction_type = sanitizeInput($_POST['transaction_type'] ?? 'all');
    $status = sanitizeInput($_POST['status'] ?? 'all');

    if ($start_date && $end_date) {
        $start_date = date('Y-m-d 00:00:00', strtotime($start_date));
        $end_date = date('Y-m-d 23:59:59', strtotime($end_date));
        if (strtotime($start_date) > strtotime($end_date)) {
            $error = "Start date must be earlier than end date.";
        }
    } else {
        $start_date = null;
        $end_date = null;
    }

    if (!isset($error)) {
        try {
            $query = "SELECT t.*, 
                i.item_name AS item_name_sell, 
                br.item_name AS item_name_buy, 
                ub.username AS buyer, 
                us.username AS seller,
                i.supplier_name AS supplier_name_sell,
                i.description AS description_sell,
                br.description AS description_buy,
                i.price AS original_price_sell,
                br.max_price AS max_price_buy
            FROM transactions t 
            LEFT JOIN items i ON t.item_id = i.id 
            LEFT JOIN buy_requests br ON t.request_id = br.id 
            JOIN users ub ON t.buyer_or_seller_id = ub.id 
            LEFT JOIN users us ON (i.posted_by = us.id OR br.user_id = us.id) 
            WHERE (i.posted_by = :user_id1 OR br.user_id = :user_id2)";
            $params = [
                ':user_id1' => $_SESSION['user_id'],
                ':user_id2' => $_SESSION['user_id']
            ];

            if ($start_date && $end_date) {
                $query .= " AND t.created_at BETWEEN :start_date AND :end_date";
                $params[':start_date'] = $start_date;
                $params[':end_date'] = $end_date;
            }

            if ($transaction_type !== 'all') {
                if ($transaction_type == 'sell') {
                    $query .= " AND t.item_id IS NOT NULL";
                } elseif ($transaction_type == 'buy') {
                    $query .= " AND t.request_id IS NOT NULL";
                }
            }

            $stmt = $pdo->prepare($query);
            $stmt->execute($params);
            $report_transactions = $stmt->fetchAll();

            $items_query = "SELECT i.*, u.username AS posted_by_name 
                FROM items i 
                JOIN users u ON i.posted_by = u.id 
                WHERE i.posted_by = :user_id";
            $items_params = [':user_id' => $_SESSION['user_id']];
            if ($start_date && $end_date) {
                $items_query .= " AND i.created_at BETWEEN :start_date AND :end_date";
                $items_params[':start_date'] = $start_date;
                $items_params[':end_date'] = $end_date;
            }
            if ($status !== 'all') {
                $items_query .= " AND i.status = :status";
                $items_params[':status'] = $status;
            }
            $stmt = $pdo->prepare($items_query);
            $stmt->execute($items_params);
            $report_items = $stmt->fetchAll();

            $requests_query = "SELECT br.*, u.username 
                FROM buy_requests br 
                JOIN users u ON br.user_id = u.id 
                WHERE br.user_id = :user_id";
            $requests_params = [':user_id' => $_SESSION['user_id']];
            if ($start_date && $end_date) {
                $requests_query .= " AND br.created_at BETWEEN :start_date AND :end_date";
                $requests_params[':start_date'] = $start_date;
                $requests_params[':end_date'] = $end_date;
            }
            if ($status !== 'all') {
                $requests_query .= " AND br.status = :status";
                $requests_params[':status'] = $status;
            }
            $stmt = $pdo->prepare($requests_query);
            $stmt->execute($requests_params);
            $report_requests = $stmt->fetchAll();

            if (isset($_POST['export_csv'])) {
                header('Content-Type: text/csv');
                header('Content-Disposition: attachment; filename="admin_report_' . date('Y-m-d_H-i-s') . '.csv"');
                $output = fopen('php://output', 'w');

                fputcsv($output, ['Transactions Report']);
                fputcsv($output, ['ID', 'Item Name', 'Type', 'Buyer', 'Seller', 'Supplier', 'Original Price/Max Price', 'Final Price', 'Quantity', 'Total Amount', 'Description', 'Date']);
                foreach ($report_transactions as $t) {
                    $item_name = $t['item_name_sell'] ?? $t['item_name_buy'] ?? 'N/A';
                    $type = $t['item_id'] ? 'Sell' : 'Buy';
                    $supplier = $t['supplier_name_sell'] ?? 'N/A';
                    $original_price = $t['item_id'] ? ($t['original_price_sell'] ?? 'N/A') : ($t['max_price_buy'] ?? 'N/A');
                    $description = $t['description_sell'] ?? $t['description_buy'] ?? 'N/A';
                    $total_amount = $t['final_price'] * $t['quantity'];
                    fputcsv($output, [
                        $t['id'],
                        $item_name,
                        $type,
                        $t['buyer'],
                        $t['seller'],
                        $supplier,
                        $original_price,
                        $t['final_price'],
                        $t['quantity'],
                        $total_amount,
                        $description,
                        $t['created_at']
                    ]);
                }

                fputcsv($output, []);
                fputcsv($output, ['Inventory Report']);
                fputcsv($output, ['ID', 'Item Name', 'Supplier', 'Description', 'Price', 'Quantity', 'Status', 'Posted By', 'Created At']);
                foreach ($report_items as $item) {
                    fputcsv($output, [
                        $item['id'],
                        $item['item_name'],
                        $item['supplier_name'] ?? 'N/A',
                        $item['description'],
                        $item['price'],
                        $item['quantity'],
                        $item['status'],
                        $item['posted_by_name'],
                        $item['created_at']
                    ]);
                }

                fputcsv($output, []);
                fputcsv($output, ['Buy Requests Report']);
                fputcsv($output, ['ID', 'Item Name', 'Description', 'Max Price', 'Quantity', 'Status', 'User', 'Created At']);
                foreach ($report_requests as $request) {
                    fputcsv($output, [
                        $request['id'],
                        $request['item_name'],
                        $request['description'],
                        $request['max_price'],
                        $request['quantity'],
                        $request['status'],
                        $request['username'],
                        $request['created_at']
                    ]);
                }

                fclose($output);
                exit();
            }
        } catch (PDOException $e) {
            $error = "Error generating report: " . $e->getMessage();
        }
    }
}

// Fetch counts for dashboard
$items_for_sell = $buy_requests = $pending_offers = 0;
try {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM items WHERE posted_by = :user_id");
    $stmt->execute([':user_id' => $_SESSION['user_id']]);
    $items_for_sell = $stmt->fetchColumn();

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM buy_requests WHERE user_id = :user_id");
    $stmt->execute([':user_id' => $_SESSION['user_id']]);
    $buy_requests = $stmt->fetchColumn();

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM offers o JOIN items i ON o.item_id = i.id WHERE i.posted_by = :user_id AND o.status = 'pending'");
    $stmt->execute([':user_id' => $_SESSION['user_id']]);
    $pending_buy_offers = $stmt->fetchColumn();

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM offers o JOIN buy_requests br ON o.request_id = br.id WHERE br.user_id = :user_id AND o.status = 'pending'");
    $stmt->execute([':user_id' => $_SESSION['user_id']]);
    $pending_sell_offers = $stmt->fetchColumn();

    $pending_offers = $pending_buy_offers + $pending_sell_offers;
} catch (PDOException $e) {
    $error = "Error fetching dashboard stats: " . $e->getMessage();
}

// Fetch items below min stock
$min_stock = 5;
$low_stock_items = [];
try {
    $stmt = $pdo->prepare("SELECT item_name FROM items WHERE quantity < :min_stock AND status = 'open' AND posted_by = :user_id");
    $stmt->execute([
        ':min_stock' => $min_stock,
        ':user_id' => $_SESSION['user_id']
    ]);
    $low_stock_items = $stmt->fetchAll(PDO::FETCH_COLUMN);
} catch (PDOException $e) {
    $error = "Error fetching low stock items: " . $e->getMessage();
}

// Pagination setup
$items_per_page = 10;
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$offset = ($page - 1) * $items_per_page;

// Fetch items for sale with pagination
$items = [];
$total_items = 0;
try {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM items WHERE posted_by = :user_id");
    $stmt->execute([':user_id' => $_SESSION['user_id']]);
    $total_items = $stmt->fetchColumn();
    
    $stmt = $pdo->prepare("SELECT i.*, u.username AS posted_by_name 
        FROM items i 
        JOIN users u ON i.posted_by = u.id 
        WHERE i.posted_by = :user_id 
        LIMIT :limit OFFSET :offset");
    // Bind all parameters using bindValue
    $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    $stmt->bindValue(':limit', $items_per_page, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute(); // No parameters passed here
    $items = $stmt->fetchAll();
} catch (PDOException $e) {
    $error = "Error fetching items: " . $e->getMessage();
}

// Fetch buy requests with pagination
$requests = [];
$total_requests = 0;
try {
    // Get total count
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM buy_requests WHERE user_id = :user_id");
    $stmt->execute([':user_id' => $_SESSION['user_id']]);
    $total_requests = $stmt->fetchColumn();
    
    // Fetch paginated requests
    $stmt = $pdo->prepare("SELECT br.*, u.username 
        FROM buy_requests br 
        JOIN users u ON br.user_id = u.id 
        WHERE br.user_id = :user_id 
        ORDER BY br.created_at DESC 
        LIMIT :limit OFFSET :offset");
    
    // Bind parameters with proper types
    $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    $stmt->bindValue(':limit', $items_per_page, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    
    $stmt->execute();
    $requests = $stmt->fetchAll();
} catch (PDOException $e) {
    error_log("Error fetching buy requests: " . $e->getMessage());
    $error = "An error occurred while fetching buy requests. Please try again.";
}

// Fetch pending offers with secure sorting
$buy_offers = $sell_offers = [];
try {
    $buy_sort_field = sanitizeInput($_GET['buy_sort_field'] ?? 'offered_price');
    $buy_sort_order = sanitizeInput($_GET['buy_sort_order'] ?? 'ASC');
    $sell_sort_field = sanitizeInput($_GET['sell_sort_field'] ?? 'offered_price');
    $sell_sort_order = sanitizeInput($_GET['sell_sort_order'] ?? 'ASC');

    $valid_fields = ['offered_price', 'created_at'];
    $valid_orders = ['ASC', 'DESC'];
    $buy_sort_field = in_array($buy_sort_field, $valid_fields) ? $buy_sort_field : 'offered_price';
    $buy_sort_order = in_array($buy_sort_order, $valid_orders) ? $buy_sort_order : 'ASC';
    $sell_sort_field = in_array($sell_sort_field, $valid_fields) ? $sell_sort_field : 'offered_price';
    $sell_sort_order = in_array($sell_sort_order, $valid_orders) ? $sell_sort_order : 'ASC';

    $stmt = $pdo->prepare("SELECT o.*, i.item_name, u.username 
        FROM offers o 
        JOIN items i ON o.item_id = i.id 
        JOIN users u ON o.user_id = u.id 
        WHERE i.posted_by = :user_id AND o.status = 'pending' 
        ORDER BY o.$buy_sort_field $buy_sort_order");
    $stmt->execute([':user_id' => $_SESSION['user_id']]);
    $buy_offers = $stmt->fetchAll();

    $stmt = $pdo->prepare("SELECT o.*, br.item_name, u.username 
        FROM offers o 
        JOIN buy_requests br ON o.request_id = br.id 
        JOIN users u ON o.user_id = u.id 
        WHERE br.user_id = :user_id AND o.status = 'pending' 
        ORDER BY o.$sell_sort_field $sell_sort_order");
    $stmt->execute([':user_id' => $_SESSION['user_id']]);
    $sell_offers = $stmt->fetchAll();
} catch (PDOException $e) {
    $error = "Error fetching offers: " . $e->getMessage();
}

// Fetch transactions with pagination
$transactions = [];
$total_transactions = 0;
try {
    // Fetch total transactions
    $stmt = $pdo->prepare("SELECT COUNT(*) 
        FROM transactions t 
        LEFT JOIN items i ON t.item_id = i.id 
        LEFT JOIN buy_requests br ON t.request_id = br.id 
        WHERE (i.posted_by = :user_id1 OR br.user_id = :user_id2)");
    $stmt->bindValue(':user_id1', $_SESSION['user_id'], PDO::PARAM_INT);
    $stmt->bindValue(':user_id2', $_SESSION['user_id'], PDO::PARAM_INT);
    $stmt->execute();
    $total_transactions = $stmt->fetchColumn();

    // Fetch paginated transactions
    $stmt = $pdo->prepare("SELECT t.*, 
        i.item_name AS item_name_sell, 
        br.item_name AS item_name_buy, 
        ub.username AS buyer, 
        us.username AS seller 
    FROM transactions t 
    LEFT JOIN items i ON t.item_id = i.id 
    LEFT JOIN buy_requests br ON t.request_id = br.id 
    JOIN users ub ON t.buyer_or_seller_id = ub.id 
    LEFT JOIN users us ON (i.posted_by = us.id OR br.user_id = us.id) 
    WHERE (i.posted_by = :user_id1 OR br.user_id = :user_id2) 
    LIMIT :limit OFFSET :offset");
    $stmt->bindValue(':user_id1', $_SESSION['user_id'], PDO::PARAM_INT);
    $stmt->bindValue(':user_id2', $_SESSION['user_id'], PDO::PARAM_INT);
    $stmt->bindValue(':limit', $items_per_page, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $transactions = $stmt->fetchAll();
} catch (PDOException $e) {
    $error = "Error fetching transactions: " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="robots" content="noindex, nofollow">
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="../css/admin.css">
    <link rel="stylesheet" href="../css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Ubuntu:ital,wght@0,300;0,400;0,500;0,700;1,300;1,400;1,500;1,700&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="../javaScript/scripts.js"></script>
</head>

<body>
<!-- Navbar -->
<nav class="navbar">
    <div class="inner-width">
        <a href="index.php" class="logo"></a>
        <button class="menu-toggler">
            <span></span>
            <span></span>
            <span></span>
        </button>
        <div class="navbar-menu">
            <a href="../index.php">Home</a>
            <a href="../index.php#about">About</a>
            <a href="../index.php#contact">Contact</a>
            <a href="admin_dashboard.php" class="active">Dashboard</a>
            <a href="logout.php">Logout</a>
        </div>
    </div>
</nav>

<!-- Admin Header -->
<div class="admin-header">
    <div class="inner-width">
        <h1>Welcome, <?php echo htmlspecialchars($admin_name, ENT_QUOTES, 'UTF-8'); ?></h1>
        <p>Manage your inventory, sales, and purchases efficiently</p>
    </div>
</div>

<div class="admin-dashboard">
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="logo">
            <i class="fas fa-user-shield"></i>
            <span>Admin Panel</span>
        </div>
        <ul>
            <li><a href="?action=dashboard"><i class="fas fa-tachometer-alt"></i> Dashboard</a></li>
            <li><a href="?action=post_sell"><i class="fas fa-tag"></i> Post Sell Item</a></li>
            <li><a href="?action=post_buy"><i class="fas fa-shopping-cart"></i> Post Buy Item</a></li>
            <li><a href="?action=items_for_sell"><i class="fas fa-box-open"></i> Items for Sale</a></li>
            <li><a href="?action=buy_requests"><i class="fas fa-hand-holding-usd"></i> Active Buy Requests</a></li>
            <li><a href="?action=offers"><i class="fas fa-exchange-alt"></i> Offers</a></li>
            <li><a href="?action=transactions"><i class="fas fa-receipt"></i> Transactions</a></li>
            <li><a href="?action=report"><i class="fas fa-chart-pie"></i> Reports</a></li>
            <li><a href="?action=add_item_type"><i class="fas fa-list"></i> Manage Item Types</a></li>
            <li><a href="../logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <?php if (isset($error)): ?>
            <div class="alert-card error">
                <p><i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
            </div>
        <?php endif; ?>
        
        <?php if (isset($success)): ?>
            <div class="alert-card success">
                <p><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></p>
            </div>
        <?php endif; ?>

        <?php if (!isset($_GET['action']) || $_GET['action'] == 'dashboard'): ?>
            <!-- Dashboard Overview -->
            <div class="dashboard-stats">
                <div class="row">
                    <div class="col-md-4">
                        <div class="stat-card">
                            <i class="fas fa-tag"></i>
                            <div class="stat-number"><?php echo htmlspecialchars($items_for_sell, ENT_QUOTES, 'UTF-8'); ?></div>
                            <h3>Items for Sale</h3>
                            <p>Total items in inventory</p>
                            <a href="?action=items_for_sell" class="admin-btn">View Items</a>
                        </div>
                    </div>
                    
                    <div class="col-md-4">
                        <div class="stat-card">
                            <i class="fas fa-shopping-cart"></i>
                            <div class="stat-number"><?php echo htmlspecialchars($buy_requests, ENT_QUOTES, 'UTF-8'); ?></div>
                            <h3>Active Buy Requests</h3>
                            <p>Total purchase requests</p>
                            <a href="?action=buy_requests" class="admin-btn">View Requests</a>
                        </div>
                    </div>
                    
                    <div class="col-md-4">
                        <div class="stat-card">
                            <i class="fas fa-exchange-alt"></i>
                            <div class="stat-number"><?php echo htmlspecialchars($pending_offers, ENT_QUOTES, 'UTF-8'); ?></div>
                            <h3>Pending Offers</h3>
                            <p>Offers awaiting your response</p>
                            <a href="?action=offers" class="admin-btn">View Offers</a>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Alerts Section -->
            <div class="alert-card warning">
                <h3><i class="fas fa-exclamation-triangle"></i> Low Stock Alerts</h3>
                <?php if (!empty($low_stock_items)): ?>
                    <ul>
                        <?php foreach ($low_stock_items as $item): ?>
                            <li><?php echo htmlspecialchars($item, ENT_QUOTES, 'UTF-8'); ?> - Needs restocking</li>
                        <?php endforeach; ?>
                    </ul>
                <?php else: ?>
                    <p>All items are sufficiently stocked.</p>
                <?php endif; ?>
            </div>
            
            <!-- Quick Actions -->
            <div class="row quick-actions">
                <div class="col-md-6">
                    <a href="?action=post_sell" class="admin-btn">
                        <i class="fas fa-plus"></i> Add New Item
                    </a>
                </div>
                <div class="col-md-6">
                    <a href="?action=post_buy" class="admin-btn">
                        <i class="fas fa-hand-holding-usd"></i> Create Buy Request
                    </a>
                </div>
            </div>

        <?php elseif ($_GET['action'] == 'post_sell'): ?>
            <!-- Post Sell Item Form -->
            <div class="form-card" style="background: #f8f9fa; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: #2c3e50; margin-bottom: 25px; text-align: center; font-size: 24px;"><i class="fas fa-tag"></i> Post Item for Sale</h2>
                <form method="POST" enctype="multipart/form-data" style="max-width: 700px; margin: 0 auto;">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Supplier Name</label>
                        <input type="text" name="supplier_name" class="input" placeholder="Enter supplier name" required 
                            style="width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; background: #fff;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Item Name</label>
                        <input type="text" name="item_name" class="input" placeholder="Enter item name" required 
                            style="width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; background: #fff;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Item Type</label>
                        <select name="item_type" id="item_type" class="input" required 
                            style="width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; background: #fff;">
                            <option value="">Select Item Type</option>
                            <?php
                            $stmt = $pdo->query("SELECT type_name FROM item_types");
                            while ($type = $stmt->fetch(PDO::FETCH_ASSOC)) {
                                echo "<option value='" . htmlspecialchars($type['type_name']) . "'>" . htmlspecialchars($type['type_name']) . "</option>";
                            }
                            ?>
                        </select>
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Description</label>
                        <textarea name="description" class="input" placeholder="Enter item description" rows="4" required 
                            style="width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; background: #fff;"></textarea>
                    </div>
                    
                    <div class="form-row" style="display: flex; gap: 15px; margin-bottom: 15px;">
                        <div class="form-group" style="flex: 1;">
                            <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Price ($)</label>
                            <input type="number" name="price" class="input" placeholder="Enter price" step="0.01" required 
                                style="width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; background: #fff;" />
                        </div>
                        
                        <div class="form-group" style="flex: 1;">
                            <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Quantity</label>
                            <input type="number" name="quantity" class="input" placeholder="Enter quantity" required 
                                style="width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; background: #fff;" />
                        </div>
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Close Time (optional)</label>
                        <input type="datetime-local" name="close_time" id="close_time" class="input" 
                            style="width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; background: #fff;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 20px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Upload Image (optional)</label>
                        <input type="file" name="image" id="item_image" class="input" accept="image/*" 
                            style="width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; background: #fff;" />
                    </div>
                    
                    <button type="submit" class="admin-btn" 
                        style="width: 100%; padding: 12px; background: #3498db; color: white; border: none; border-radius: 4px; font-size: 14px; cursor: pointer; transition: background 0.3s;">
                        <i class="fas fa-save"></i> Submit Item
                    </button>
                </form>
            </div>

        <?php elseif ($_GET['action'] == 'edit_item' && isset($item_to_edit)): ?>
            <!-- Edit Item Form -->
            <div class="form-card">
                <h2><i class="fas fa-edit"></i> Edit Item</h2>
                <form method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="existing_image" value="<?php echo htmlspecialchars($item_to_edit['image'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                    <div class="form-group">
                        <label>Supplier Name:</label>
                        <input type="text" name="supplier_name" class="input" value="<?php echo htmlspecialchars($item_to_edit['supplier_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required />
                    </div>
                    <div class="form-group">
                        <label>Item Name:</label>
                        <input type="text" name="item_name" class="input" value="<?php echo htmlspecialchars($item_to_edit['item_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required />
                    </div>
                    <div class="form-group">
                        <label for="item_type">Item Type:</label>
                        <select name="item_type" id="item_type" class="input" required>
                            <?php
                            $stmt = $pdo->query("SELECT type_name FROM item_types");
                            while ($type = $stmt->fetch(PDO::FETCH_ASSOC)) {
                                $selected = ($type['type_name'] === $item_to_edit['item_type']) ? 'selected' : '';
                                echo "<option value='" . htmlspecialchars($type['type_name']) . "' $selected>" . htmlspecialchars($type['type_name']) . "</option>";
                            }
                            ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Description:</label>
                        <textarea name="description" class="input" rows="4" required><?php echo htmlspecialchars($item_to_edit['description'] ?? '', ENT_QUOTES, 'UTF-8'); ?></textarea>
                    </div>
                    <div class="form-group">
                        <label>Price ($):</label>
                        <input type="number" name="price" class="input" value="<?php echo htmlspecialchars($item_to_edit['price'] ?? 0, ENT_QUOTES, 'UTF-8'); ?>" step="0.01" required />
                    </div>
                    <div class="form-group">
                        <label>Quantity:</label>
                        <input type="number" name="quantity" class="input" value="<?php echo htmlspecialchars($item_to_edit['quantity'] ?? 0, ENT_QUOTES, 'UTF-8'); ?>" required />
                    </div>
                    <div class="form-group">
                        <label>Close Time (optional):</label>
                        <input type="datetime-local" name="close_time" id="close_time" class="input" value="<?php echo !empty($item_to_edit['close_time']) && strtotime($item_to_edit['close_time']) ? date('Y-m-d\TH:i', strtotime($item_to_edit['close_time'])) : ''; ?>" />
                    </div>
                    <div class="form-group">
                        <label>Current Image:</label>
                        <?php if (!empty($item_to_edit['image']) && file_exists('../' . $item_to_edit['image'])): ?>
                            <img src="../<?php echo htmlspecialchars($item_to_edit['image'], ENT_QUOTES, 'UTF-8'); ?>" alt="Current Image" class="item-image" style="max-width: 200px;">
                        <?php else: ?>
                            <p>No image uploaded.</p>
                        <?php endif; ?>
                        <label for="item_image">Upload New Image (optional):</label>
                        <input type="file" name="image" id="item_image" class="input" accept="image/*" />
                    </div>
                    <button type="submit" class="admin-btn full-width">
                        <i class="fas fa-save"></i> Update Item
                    </button>
                    <a href="?action=items_for_sell" class="admin-btn danger full-width">
                        <i class="fas fa-arrow-left"></i> Cancel
                    </a>
                </form>
            </div>

        <?php elseif ($_GET['action'] == 'post_buy'): ?>
            <!-- Post Buy Item Form -->
            <div class="form-card" style="background: #f8f9fa; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: #2c3e50; margin-bottom: 25px; text-align: center; font-size: 24px;"><i class="fas fa-hand-holding-usd"></i> Post Buy Request</h2>
                <form method="POST" enctype="multipart/form-data" style="max-width: 700px; margin: 0 auto;">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Item Name</label>
                        <input type="text" name="item_name" class="input" placeholder="Enter item name" required 
                            style="width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; background: #fff;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Item Type</label>
                        <select name="item_type" id="item_type" class="input" required 
                            style="width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; background: #fff;">
                            <option value="">Select Item Type</option>
                            <?php
                            $stmt = $pdo->query("SELECT type_name FROM item_types");
                            while ($type = $stmt->fetch(PDO::FETCH_ASSOC)) {
                                echo "<option value='" . htmlspecialchars($type['type_name']) . "'>" . htmlspecialchars($type['type_name']) . "</option>";
                            }
                            ?>
                        </select>
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Description</label>
                        <textarea name="description" class="input" placeholder="Enter item description" rows="4" required 
                            style="width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; background: #fff;"></textarea>
                    </div>
                    
                    <div class="form-row" style="display: flex; gap: 15px; margin-bottom: 15px;">
                        <div class="form-group" style="flex: 1;">
                            <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Max Price ($)</label>
                            <input type="number" name="max_price" class="input" placeholder="Enter max price" step="0.01" required 
                                style="width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; background: #fff;" />
                        </div>
                        
                        <div class="form-group" style="flex: 1;">
                            <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Quantity</label>
                            <input type="number" name="quantity" class="input" placeholder="Enter quantity" required 
                                style="width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; background: #fff;" />
                        </div>
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Close Time (optional)</label>
                        <input type="datetime-local" name="close_time" id="close_time" class="input" 
                            style="width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; background: #fff;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 20px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Upload Image (optional)</label>
                        <input type="file" name="image" id="buy_image" class="input" accept="image/*" 
                            style="width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; background: #fff;" />
                    </div>
                    
                    <button type="submit" class="admin-btn" 
                        style="width: 100%; padding: 12px; background: #3498db; color: white; border: none; border-radius: 4px; font-size: 14px; cursor: pointer; transition: background 0.3s;">
                        <i class="fas fa-paper-plane"></i> Submit Request
                    </button>
                </form>
            </div>

        <?php elseif ($_GET['action'] == 'items_for_sell'): ?>
            <!-- Items for Sell -->
            <h2><i class="fas fa-box-open"></i> Items for Sale (<?php echo htmlspecialchars($total_items, ENT_QUOTES, 'UTF-8'); ?>)</h2>
            <?php if ($items): ?>
                <div class="row">
                    <?php foreach ($items as $item): ?>
                        <div class="col-md-6">
                            <div class="item-card <?php echo ($item['status'] === 'closed') ? 'closed-item' : ''; ?>">
                                <?php if (!empty($item['image'])): ?>
                                    <img src="../<?php echo htmlspecialchars($item['image'], ENT_QUOTES, 'UTF-8'); ?>" alt="<?php echo htmlspecialchars($item['item_name'], ENT_QUOTES, 'UTF-8'); ?>" class="item-image">
                                <?php endif; ?>
                                <h3><?php echo htmlspecialchars($item['item_name'], ENT_QUOTES, 'UTF-8'); ?></h3>
                                <p><strong>Type:</strong> <?php echo htmlspecialchars($item['item_type'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></p>
                                <p><strong>Supplier:</strong> <?php echo htmlspecialchars($item['supplier_name'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></p>
                                <p><?php echo htmlspecialchars($item['description'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p class="price">Price: $<?php echo number_format($item['price'], 2); ?></p>
                                <p class="quantity">Quantity: <?php echo htmlspecialchars($item['quantity'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <?php if (!empty($item['close_time']) && $item['status'] === 'open'): ?>
                                    <p class="countdown" data-close-time="<?php echo htmlspecialchars($item['close_time'], ENT_QUOTES, 'UTF-8'); ?>">
                                        Closes in: <span class="countdown-timer"></span>
                                    </p>
                                <?php elseif (!empty($item['close_time'])): ?>
                                    <p><strong>Closed At:</strong> <?php echo htmlspecialchars($item['close_time'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <?php endif; ?>
                                <div class="item-details">
                                    <p><strong>Posted By:</strong> <?php echo htmlspecialchars($item['posted_by_name'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Created At:</strong> <?php echo htmlspecialchars($item['created_at'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Status:</strong> <?php echo htmlspecialchars($item['status'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></p>
                                </div>
                                <div class="item-actions">
                                    <a href="?action=edit_item&item_id=<?php echo htmlspecialchars($item['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn">
                                        <i class="fas fa-edit"></i> Edit
                                    </a>
                                    <?php if ($item['status'] !== 'closed'): ?>
                                        <a href="?action=close_item&item_id=<?php echo htmlspecialchars($item['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn warning" onclick="return confirm('Are you sure you want to mark this item as closed? It will no longer be available for offers, but will remain in your inventory.');">
                                            <i class="fas fa-times"></i> Mark as Closed
                                        </a>
                                    <?php else: ?>
                                        <a href="?action=reopen_item&item_id=<?php echo htmlspecialchars($item['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn reopen" onclick="return confirm('Are you sure you want to reopen this item? It will become available for offers again.');">
                                            <i class="fas fa-undo"></i> Reopen
                                        </a>
                                    <?php endif; ?>
                                    <a href="?action=delete_item&item_id=<?php echo htmlspecialchars($item['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to permanently delete this item? All related offers and transactions will also be deleted, and this action cannot be undone.');">
                                        <i class="fas fa-trash"></i> Delete
                                    </a>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
                               <!-- Pagination -->
                               <div class="pagination">
                    <?php
                    $total_pages = ceil($total_items / $items_per_page);
                    if ($page > 1) {
                        echo "<a href='?action=items_for_sell&page=" . ($page - 1) . "'>« Previous</a>";
                    }

                    // Display page numbers
                    for ($i = 1; $i <= $total_pages; $i++) {
                        if ($i == $page) {
                            echo "<span class='current-page'>$i</span>";
                        } else {
                            echo "<a href='?action=items_for_sell&page=$i'>$i</a>";
                        }
                    }

                    if ($page < $total_pages) {
                        echo "<a href='?action=items_for_sell&page=" . ($page + 1) . "'>Next »</a>";
                    }
                    ?>
                </div>
            <?php else: ?>
                <p>No items available for sale.</p>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'buy_requests'): ?>
            <!-- Active Buy Requests -->
            <h2><i class="fas fa-hand-holding-usd"></i> Active Buy Requests (<?php echo htmlspecialchars($total_requests, ENT_QUOTES, 'UTF-8'); ?>)</h2>
            <?php if ($requests): ?>
                <div class="row">
                    <?php foreach ($requests as $request): ?>
                        <div class="col-md-6">
                            <div class="item-card <?php echo ($request['status'] === 'closed') ? 'closed-item' : ''; ?>">
                                <?php if (!empty($request['image'])): ?>
                                    <img src="../<?php echo htmlspecialchars($request['image'], ENT_QUOTES, 'UTF-8'); ?>" alt="<?php echo htmlspecialchars($request['item_name'], ENT_QUOTES, 'UTF-8'); ?>" class="item-image">
                                <?php endif; ?>
                                <h3><?php echo htmlspecialchars($request['item_name'], ENT_QUOTES, 'UTF-8'); ?></h3>
                                <p><strong>Type:</strong> <?php echo htmlspecialchars($request['item_type'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></p>
                                <p><?php echo htmlspecialchars($request['description'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p class="price">Max Price: $<?php echo number_format($request['max_price'], 2); ?></p>
                                <p class="quantity">Quantity: <?php echo htmlspecialchars($request['quantity'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <?php if (!empty($request['close_time']) && $request['status'] === 'open'): ?>
                                    <p class="countdown" data-close-time="<?php echo htmlspecialchars($request['close_time'], ENT_QUOTES, 'UTF-8'); ?>">
                                        Closes in: <span class="countdown-timer"></span>
                                    </p>
                                <?php elseif (!empty($request['close_time'])): ?>
                                    <p><strong>Closed At:</strong> <?php echo htmlspecialchars($request['close_time'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <?php endif; ?>
                                <div class="item-details">
                                    <p><strong>Posted By:</strong> <?php echo htmlspecialchars($request['username'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Created At:</strong> <?php echo htmlspecialchars($request['created_at'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Status:</strong> <?php echo htmlspecialchars($request['status'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></p>
                                </div>
                                <div class="item-actions">
                                    <?php if ($request['status'] === 'open'): ?>
                                        <a href="?action=view_offers&request_id=<?php echo htmlspecialchars($request['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn">
                                            <i class="fas fa-eye"></i> View Offers
                                        </a>
                                        <a href="?action=cancel_buy_request&request_id=<?php echo htmlspecialchars($request['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn warning" onclick="return confirm('Are you sure you want to cancel this buy request? It will no longer accept offers.');">
                                            <i class="fas fa-times"></i> Cancel Request
                                        </a>
                                    <?php else: ?>
                                        <a href="?action=reopen_buy_request&request_id=<?php echo htmlspecialchars($request['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn reopen" onclick="return confirm('Are you sure you want to reopen this buy request? It will start accepting offers again.');">
                                            <i class="fas fa-undo"></i> Reopen
                                        </a>
                                    <?php endif; ?>
                                    <a href="?action=delete_buy_request&request_id=<?php echo htmlspecialchars($request['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to permanently delete this buy request? All related offers and transactions will also be deleted, and this action cannot be undone.');">
                                        <i class="fas fa-trash"></i> Delete
                                    </a>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
                <!-- Pagination -->
                <div class="pagination">
                    <?php
                    $total_pages = ceil($total_requests / $items_per_page);
                    if ($page > 1) {
                        echo "<a href='?action=buy_requests&page=" . ($page - 1) . "'>« Previous</a>";
                    }
                    for ($i = 1; $i <= $total_pages; $i++) {
                        if ($i == $page) {
                            echo "<span class='current-page'>$i</span>";
                        } else {
                            echo "<a href='?action=buy_requests&page=$i'>$i</a>";
                        }
                    }
                    if ($page < $total_pages) {
                        echo "<a href='?action=buy_requests&page=" . ($page + 1) . "'>Next »</a>";
                    }
                    ?>
                </div>
            <?php else: ?>
                <p>No active buy requests found.</p>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'view_offers' && isset($buy_request_offers)): ?>
            <!-- View Offers for Buy Request -->
            <h2><i class="fas fa-exchange-alt"></i> Offers for Buy Request</h2>
            <?php if ($buy_request_offers): ?>
                <div class="row">
                    <?php foreach ($buy_request_offers as $offer): ?>
                        <div class="col-md-6">
                            <div class="item-card">
                                <h3>Offer for <?php echo htmlspecialchars($offer['item_name'], ENT_QUOTES, 'UTF-8'); ?></h3>
                                <p><strong>Offered By:</strong> <?php echo htmlspecialchars($offer['username'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p class="price">Offered Price: $<?php echo number_format($offer['offered_price'], 2); ?></p>
                                <p class="quantity">Quantity: <?php echo htmlspecialchars($offer['quantity'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p><strong>Created At:</strong> <?php echo htmlspecialchars($offer['created_at'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p><strong>Status:</strong> <?php echo htmlspecialchars($offer['status'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <div class="item-actions">
                                    <a href="?action=offer_action&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>&type=accept" class="admin-btn" onclick="return confirm('Are you sure you want to accept this offer? This will create a transaction and update quantities.');">
                                        <i class="fas fa-check"></i> Accept
                                    </a>
                                    <a href="?action=offer_action&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>&type=reject" class="admin-btn warning" onclick="return confirm('Are you sure you want to reject this offer?');">
                                        <i class="fas fa-times"></i> Reject
                                    </a>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
                <a href="?action=buy_requests" class="admin-btn"><i class="fas fa-arrow-left"></i> Back to Buy Requests</a>
            <?php else: ?>
                <p>No pending offers for this buy request.</p>
                <a href="?action=buy_requests" class="admin-btn"><i class="fas fa-arrow-left"></i> Back to Buy Requests</a>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'offers'): ?>
            <!-- Pending Offers -->
            <h2><i class="fas fa-exchange-alt"></i> Pending Offers</h2>
            <!-- Offers for Your Items (Buy Offers) -->
            <h3>Offers for Your Items</h3>
            <?php if ($buy_offers): ?>
                <div class="sort-controls">
                    <form method="GET">
                        <input type="hidden" name="action" value="offers">
                        <label for="buy_sort_field">Sort By:</label>
                        <select name="buy_sort_field" id="buy_sort_field">
                            <option value="offered_price" <?php echo $buy_sort_field == 'offered_price' ? 'selected' : ''; ?>>Price</option>
                            <option value="created_at" <?php echo $buy_sort_field == 'created_at' ? 'selected' : ''; ?>>Date</option>
                        </select>
                        <select name="buy_sort_order">
                            <option value="ASC" <?php echo $buy_sort_order == 'ASC' ? 'selected' : ''; ?>>Ascending</option>
                            <option value="DESC" <?php echo $buy_sort_order == 'DESC' ? 'selected' : ''; ?>>Descending</option>
                        </select>
                        <button type="submit" class="admin-btn small">Sort</button>
                    </form>
                </div>
                <div class="row">
                    <?php foreach ($buy_offers as $offer): ?>
                        <div class="col-md-6">
                            <div class="item-card">
                                <h3>Offer for <?php echo htmlspecialchars($offer['item_name'], ENT_QUOTES, 'UTF-8'); ?></h3>
                                <p><strong>Offered By:</strong> <?php echo htmlspecialchars($offer['username'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p class="price">Offered Price: $<?php echo number_format($offer['offered_price'], 2); ?></p>
                                <p class="quantity">Quantity: <?php echo htmlspecialchars($offer['quantity'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p><strong>Created At:</strong> <?php echo htmlspecialchars($offer['created_at'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p><strong>Status:</strong> <?php echo htmlspecialchars($offer['status'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <div class="item-actions">
                                    <a href="?action=offer_action&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>&type=accept" class="admin-btn" onclick="return confirm('Are you sure you want to accept this offer? This will create a transaction and update quantities.');">
                                        <i class="fas fa-check"></i> Accept
                                    </a>
                                    <a href="?action=offer_action&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>&type=reject" class="admin-btn warning" onclick="return confirm('Are you sure you want to reject this offer?');">
                                        <i class="fas fa-times"></i> Reject
                                    </a>
                                    <a href="?action=close_offer&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn warning" onclick="return confirm('Are you sure you want to close this offer?');">
                                        <i class="fas fa-times-circle"></i> Close
                                    </a>
                                    <a href="?action=delete_offer&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this offer?');">
                                        <i class="fas fa-trash"></i> Delete
                                    </a>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <p>No pending offers for your items.</p>
            <?php endif; ?>

            <!-- Offers for Your Buy Requests (Sell Offers) -->
            <h3>Offers for Your Buy Requests</h3>
            <?php if ($sell_offers): ?>
                <div class="sort-controls">
                    <form method="GET">
                        <input type="hidden" name="action" value="offers">
                        <label for="sell_sort_field">Sort By:</label>
                        <select name="sell_sort_field" id="sell_sort_field">
                            <option value="offered_price" <?php echo $sell_sort_field == 'offered_price' ? 'selected' : ''; ?>>Price</option>
                            <option value="created_at" <?php echo $sell_sort_field == 'created_at' ? 'selected' : ''; ?>>Date</option>
                        </select>
                        <select name="sell_sort_order">
                            <option value="ASC" <?php echo $sell_sort_order == 'ASC' ? 'selected' : ''; ?>>Ascending</option>
                            <option value="DESC" <?php echo $sell_sort_order == 'DESC' ? 'selected' : ''; ?>>Descending</option>
                        </select>
                        <button type="submit" class="admin-btn small">Sort</button>
                    </form>
                </div>
                <div class="row">
                    <?php foreach ($sell_offers as $offer): ?>
                        <div class="col-md-6">
                            <div class="item-card">
                                <h3>Offer for <?php echo htmlspecialchars($offer['item_name'], ENT_QUOTES, 'UTF-8'); ?></h3>
                                <p><strong>Offered By:</strong> <?php echo htmlspecialchars($offer['username'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p class="price">Offered Price: $<?php echo number_format($offer['offered_price'], 2); ?></p>
                                <p class="quantity">Quantity: <?php echo htmlspecialchars($offer['quantity'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p><strong>Created At:</strong> <?php echo htmlspecialchars($offer['created_at'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p><strong>Status:</strong> <?php echo htmlspecialchars($offer['status'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <div class="item-actions">
                                    <a href="?action=offer_action&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>&type=accept" class="admin-btn" onclick="return confirm('Are you sure you want to accept this offer? This will create a transaction and update quantities.');">
                                        <i class="fas fa-check"></i> Accept
                                    </a>
                                    <a href="?action=offer_action&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>&type=reject" class="admin-btn warning" onclick="return confirm('Are you sure you want to reject this offer?');">
                                        <i class="fas fa-times"></i> Reject
                                    </a>
                                    <a href="?action=close_offer&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn warning" onclick="return confirm('Are you sure you want to close this offer?');">
                                        <i class="fas fa-times-circle"></i> Close
                                    </a>
                                    <a href="?action=delete_offer&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this offer?');">
                                        <i class="fas fa-trash"></i> Delete
                                    </a>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <p>No pending offers for your buy requests.</p>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'transactions'): ?>
            <!-- Transactions -->
            <h2><i class="fas fa-receipt"></i> Transactions (<?php echo htmlspecialchars($total_transactions, ENT_QUOTES, 'UTF-8'); ?>)</h2>
            <?php if ($transactions): ?>
                <div class="row">
                    <?php foreach ($transactions as $transaction): ?>
                        <div class="col-md-6">
                            <div class="item-card">
                                <h3>Transaction #<?php echo htmlspecialchars($transaction['id'], ENT_QUOTES, 'UTF-8'); ?></h3>
                                <p><strong>Item:</strong> <?php echo htmlspecialchars($transaction['item_name_sell'] ?? $transaction['item_name_buy'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></p>
                                <p><strong>Type:</strong> <?php echo $transaction['item_id'] ? 'Sell' : 'Buy'; ?></p>
                                <p><strong>Buyer:</strong> <?php echo htmlspecialchars($transaction['buyer'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p><strong>Seller:</strong> <?php echo htmlspecialchars($transaction['seller'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p class="price">Final Price: $<?php echo number_format($transaction['final_price'], 2); ?></p>
                                <p class="quantity">Quantity: <?php echo htmlspecialchars($transaction['quantity'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p><strong>Total Amount:</strong> $<?php echo number_format($transaction['final_price'] * $transaction['quantity'], 2); ?></p>
                                <p><strong>Date:</strong> <?php echo htmlspecialchars($transaction['created_at'], ENT_QUOTES, 'UTF-8'); ?></p>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
                <!-- Pagination -->
                <div class="pagination">
                    <?php
                    $total_pages = ceil($total_transactions / $items_per_page);
                    if ($page > 1) {
                        echo "<a href='?action=transactions&page=" . ($page - 1) . "'>« Previous</a>";
                    }
                    for ($i = 1; $i <= $total_pages; $i++) {
                        if ($i == $page) {
                            echo "<span class='current-page'>$i</span>";
                        } else {
                            echo "<a href='?action=transactions&page=$i'>$i</a>";
                        }
                    }
                    if ($page < $total_pages) {
                        echo "<a href='?action=transactions&page=" . ($page + 1) . "'>Next »</a>";
                    }
                    ?>
                </div>
            <?php else: ?>
                <p>No transactions found.</p>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'report'): ?>
            <!-- Reports -->
            <h2><i class="fas fa-chart-pie"></i> Generate Report</h2>
            <div class="form-card">
                <form method="POST" action="?action=report&generate_report=1">
                    <div class="form-group">
                        <label for="start_date">Start Date:</label>
                        <input type="date" name="start_date" id="start_date" class="input" />
                    </div>
                    <div class="form-group">
                        <label for="end_date">End Date:</label>
                        <input type="date" name="end_date" id="end_date" class="input" />
                    </div>
                    <div class="form-group">
                        <label for="transaction_type">Transaction Type:</label>
                        <select name="transaction_type" id="transaction_type" class="input">
                            <option value="all">All</option>
                            <option value="sell">Sell</option>
                            <option value="buy">Buy</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="status">Status:</label>
                        <select name="status" id="status" class="input">
                            <option value="all">All</option>
                            <option value="open">Open</option>
                            <option value="closed">Closed</option>
                        </select>
                    </div>
                    <button type="submit" class="admin-btn">
                        <i class="fas fa-eye"></i> Generate Report
                    </button>
                    <button type="submit" name="export_csv" value="1" class="admin-btn">
                        <i class="fas fa-download"></i> Export to CSV
                    </button>
                </form>
            </div>

            <?php if (isset($report_transactions) || isset($report_items) || isset($report_requests)): ?>
                <!-- Transactions Report -->
                <h3>Transactions</h3>
                <?php if ($report_transactions): ?>
                    <div class="row">
                        <?php foreach ($report_transactions as $t): ?>
                            <div class="col-md-6">
                                <div class="item-card">
                                    <h3>Transaction #<?php echo htmlspecialchars($t['id'], ENT_QUOTES, 'UTF-8'); ?></h3>
                                    <p><strong>Item:</strong> <?php echo htmlspecialchars($t['item_name_sell'] ?? $t['item_name_buy'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Type:</strong> <?php echo $t['item_id'] ? 'Sell' : 'Buy'; ?></p>
                                    <p><strong>Buyer:</strong> <?php echo htmlspecialchars($t['buyer'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Seller:</strong> <?php echo htmlspecialchars($t['seller'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Supplier:</strong> <?php echo htmlspecialchars($t['supplier_name_sell'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Original Price/Max Price:</strong> $<?php echo number_format($t['item_id'] ? ($t['original_price_sell'] ?? 0) : ($t['max_price_buy'] ?? 0), 2); ?></p>
                                    <p class="price">Final Price: $<?php echo number_format($t['final_price'], 2); ?></p>
                                    <p class="quantity">Quantity: <?php echo htmlspecialchars($t['quantity'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Total Amount:</strong> $<?php echo number_format($t['final_price'] * $t['quantity'], 2); ?></p>
                                    <p><strong>Description:</strong> <?php echo htmlspecialchars($t['description_sell'] ?? $t['description_buy'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Date:</strong> <?php echo htmlspecialchars($t['created_at'], ENT_QUOTES, 'UTF-8'); ?></p>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <p>No transactions match the criteria.</p>
                <?php endif; ?>

                <!-- Inventory Report -->
                <h3>Inventory</h3>
                <?php if ($report_items): ?>
                    <div class="row">
                        <?php foreach ($report_items as $item): ?>
                            <div class="col-md-6">
                                <div class="item-card">
                                    <h3><?php echo htmlspecialchars($item['item_name'], ENT_QUOTES, 'UTF-8'); ?></h3>
                                    <p><strong>Supplier:</strong> <?php echo htmlspecialchars($item['supplier_name'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Description:</strong> <?php echo htmlspecialchars($item['description'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p class="price">Price: $<?php echo number_format($item['price'], 2); ?></p>
                                    <p class="quantity">Quantity: <?php echo htmlspecialchars($item['quantity'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Status:</strong> <?php echo htmlspecialchars($item['status'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Posted By:</strong> <?php echo htmlspecialchars($item['posted_by_name'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Created At:</strong> <?php echo htmlspecialchars($item['created_at'], ENT_QUOTES, 'UTF-8'); ?></p>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <p>No items match the criteria.</p>
                <?php endif; ?>

                <!-- Buy Requests Report -->
                <h3>Buy Requests</h3>
                <?php if ($report_requests): ?>
                    <div class="row">
                        <?php foreach ($report_requests as $request): ?>
                            <div class="col-md-6">
                                <div class="item-card">
                                    <h3><?php echo htmlspecialchars($request['item_name'], ENT_QUOTES, 'UTF-8'); ?></h3>
                                    <p><strong>Description:</strong> <?php echo htmlspecialchars($request['description'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p class="price">Max Price: $<?php echo number_format($request['max_price'], 2); ?></p>
                                    <p class="quantity">Quantity: <?php echo htmlspecialchars($request['quantity'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Status:</strong> <?php echo htmlspecialchars($request['status'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>User:</strong> <?php echo htmlspecialchars($request['username'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p><strong>Created At:</strong> <?php echo htmlspecialchars($request['created_at'], ENT_QUOTES, 'UTF-8'); ?></p>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <p>No buy requests match the criteria.</p>
                <?php endif; ?>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'add_item_type'): ?>
            <!-- Manage Item Types -->
            <h2><i class="fas fa-list"></i> Manage Item Types</h2>
            <div class="form-card">
                <h3>Add New Item Type</h3>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                    <div class="form-group">
                        <input type="text" name="type_name" class="input" placeholder="Item Type Name" required />
                    </div>
                    <button type="submit" class="admin-btn">
                        <i class="fas fa-plus"></i> Add Item Type
                    </button>
                </form>
            </div>
            <h3>Existing Item Types</h3>
            <?php if ($item_types): ?>
                <ul class="item-type-list">
                    <?php foreach ($item_types as $type): ?>
                        <li>
                            <?php echo htmlspecialchars($type, ENT_QUOTES, 'UTF-8'); ?>
                            <a href="?action=delete_item_type&type_name=<?php echo urlencode($type); ?>" class="admin-btn danger small" onclick="return confirm('Are you sure you want to delete this item type? It can only be deleted if not in use.');">
                                <i class="fas fa-trash"></i> Delete
                            </a>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php else: ?>
                <p>No item types found.</p>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</div>

<!-- Footer -->
<footer id="footer">
    <div class="inner-width">
        <div class="row">
            <div class="col-md-4">
                <h3>About Us</h3>
                <p>We are a leading online bidding platform dedicated to connecting buyers and sellers in a secure and efficient marketplace.</p>
            </div>
            <div class="col-md-4">
                <h3>Quick Links</h3>
                <ul>
                    <li><a href="../index.php">Home</a></li>
                    <li><a href="../index.php#about">About</a></li>
                    <li><a href="../index.php#contact">Contact</a></li>
                    <li><a href="admin_dashboard.php">Dashboard</a></li>
                </ul>
            </div>
            <div class="col-md-4">
                <h3>Contact Us</h3>
                <p>Email: support@biddingplatform.com</p>
                <p>Phone: +1 234 567 890</p>
                <div class="social-links">
                    <a href="#"><i class="fab fa-facebook-f"></i></a>
                    <a href="#"><i class="fab fa-twitter"></i></a>
                    <a href="#"><i class="fab fa-instagram"></i></a>
                    <a href="#"><i class="fab fa-linkedin-in"></i></a>
                </div>
            </div>
        </div>
        <div class="copyright">
            <p>&copy; <?php echo date('Y'); ?> Online Bidding Platform. All rights reserved.</p>
        </div>
    </div>
</footer>

<script src="../javaScript/countdown.js"></script>
</body>
</html>