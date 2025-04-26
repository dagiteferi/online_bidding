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
                $description = sanitizeInput($_POST['description']);
                $price = floatval($_POST['price']);
                $quantity = intval($_POST['quantity']);
                $close_time = !empty($_POST['close_time']) ? date('Y-m-d H:i:s', strtotime($_POST['close_time'])) : null;
                $user_id = $_SESSION['user_id'];
                $image_path = null;
                $item_types = isset($_POST['item_types']) ? sanitizeInput(trim($_POST['item_types'])) : '';

                if (empty($supplier_name) || empty($item_name) || empty($description) || $price <= 0 || $quantity <= 0) {
                    $error = "All fields are required, and price/quantity must be positive.";
                    error_log("Validation failed: supplier_name='$supplier_name', item_name='$item_name', description='$description', price=$price, quantity=$quantity");
                } elseif (empty($item_types)) {
                    $error = "At least one item type is required.";
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
                            ':item_type' => $item_types,
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
                $description = sanitizeInput($_POST['description']);
                $max_price = floatval($_POST['max_price']);
                $quantity = intval($_POST['quantity']);
                $close_time = !empty($_POST['close_time']) ? date('Y-m-d H:i:s', strtotime($_POST['close_time'])) : null;
                $user_id = $_SESSION['user_id'];
                $image_path = null;
                $item_types = isset($_POST['item_types']) ? sanitizeInput(trim($_POST['item_types'])) : '';

                if (empty($item_name) || empty($description) || $max_price <= 0 || $quantity <= 0) {
                    $error = "All fields are required, and max price/quantity must be positive.";
                } elseif (empty($item_types)) {
                    $error = "At least one item type is required.";
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
                            ':item_type' => $item_types,
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

// Handle Edit Item (Items for Sale)
if (isset($_GET['action']) && $_GET['action'] == 'edit_item' && isset($_GET['item_id'])) {
    $item_id = intval($_GET['item_id']);
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            $error = "Invalid CSRF token.";
        } else {
            try {
                $supplier_name = sanitizeInput($_POST['supplier_name']);
                $item_name = sanitizeInput($_POST['item_name']);
                $description = sanitizeInput($_POST['description']);
                $price = floatval($_POST['price']);
                $quantity = intval($_POST['quantity']);
                $close_time = !empty($_POST['close_time']) ? date('Y-m-d H:i:s', strtotime($_POST['close_time'])) : null;
                $image_path = $_POST['existing_image'] ?? null;
                $item_types = isset($_POST['item_types']) ? sanitizeInput(trim($_POST['item_types'])) : '';

                if (empty($supplier_name) || empty($item_name) || empty($description) || $price <= 0 || $quantity < 0) {
                    $error = "All fields are required, and price must be positive, quantity must be non-negative.";
                } elseif (empty($item_types)) {
                    $error = "At least one item type is required.";
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
                            ':item_type' => $item_types,
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
                            header("Location: admin_dashboard.php?action=items_for_sell");
                            exit();
                        } else {
                            $error = "Item not found or you don't have permission to edit it.";
                        }
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

// Handle Edit Buy Request
if (isset($_GET['action']) && $_GET['action'] == 'edit_buy_request' && isset($_GET['request_id'])) {
    $request_id = intval($_GET['request_id']);
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            $error = "Invalid CSRF token.";
        } else {
            try {
                $item_name = sanitizeInput($_POST['item_name']);
                $description = sanitizeInput($_POST['description']);
                $max_price = floatval($_POST['max_price']);
                $quantity = intval($_POST['quantity']);
                $close_time = !empty($_POST['close_time']) ? date('Y-m-d H:i:s', strtotime($_POST['close_time'])) : null;
                $image_path = $_POST['existing_image'] ?? null;
                $item_types = isset($_POST['item_types']) ? sanitizeInput(trim($_POST['item_types'])) : '';

                if (empty($item_name) || empty($description) || $max_price <= 0 || $quantity < 0) {
                    $error = "All fields are required, and max price must be positive, quantity must be non-negative.";
                } elseif (empty($item_types)) {
                    $error = "At least one item type is required.";
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
                            if (!empty($_POST['existing_image'])) {
                                $old_image = dirname(__DIR__) . '/' . $_POST['existing_image'];
                                if (file_exists($old_image)) {
                                    unlink($old_image);
                                }
                            }
                        }
                    }

                    if (!isset($error)) {
                        $stmt = $pdo->prepare("UPDATE buy_requests SET item_name = :item_name, item_type = :item_type, description = :description, max_price = :max_price, quantity = :quantity, image = :image, close_time = :close_time WHERE id = :request_id AND user_id = :user_id");
                        $stmt->execute([
                            ':item_name' => $item_name,
                            ':item_type' => $item_types,
                            ':description' => $description,
                            ':max_price' => $max_price,
                            ':quantity' => $quantity,
                            ':image' => $image_path,
                            ':close_time' => $close_time,
                            ':request_id' => $request_id,
                            ':user_id' => $_SESSION['user_id']
                        ]);

                        if ($stmt->rowCount() > 0) {
                            $success = "Buy request updated successfully!";
                            header("Location: admin_dashboard.php?action=buy_requests");
                            exit();
                        } else {
                            $error = "Buy request not found or you don't have permission to edit it.";
                        }
                    }
                }
            } catch (PDOException $e) {
                $error = "Error updating buy request: " . $e->getMessage();
            }
        }
    } else {
        try {
            $stmt = $pdo->prepare("SELECT * FROM buy_requests WHERE id = :request_id AND user_id = :user_id");
            $stmt->execute([
                ':request_id' => $request_id,
                ':user_id' => $_SESSION['user_id']
            ]);
            $request_to_edit = $stmt->fetch();
            if (!$request_to_edit) {
                $error = "Buy request not found or you don't have permission to edit it.";
            }
        } catch (PDOException $e) {
            $error = "Error fetching buy request: " . $e->getMessage();
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

// Handle Close Buy Request
if (isset($_GET['action']) && $_GET['action'] == 'close_buy_request' && isset($_GET['request_id'])) {
    $request_id = intval($_GET['request_id']);
    try {
        $stmt = $pdo->prepare("UPDATE buy_requests SET status = 'closed' WHERE id = :request_id AND user_id = :user_id");
        $stmt->execute([
            ':request_id' => $request_id,
            ':user_id' => $_SESSION['user_id']
        ]);
        if ($stmt->rowCount() > 0) {
            $success = "Buy request closed successfully!";
        } else {
            $error = "Buy request not found or you don't have permission to close it.";
        }
        header("Location: admin_dashboard.php?action=buy_requests");
        exit();
    } catch (PDOException $e) {
        $error = "Error closing buy request: " . $e->getMessage();
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
    $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    $stmt->bindValue(':limit', $items_per_page, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $items = $stmt->fetchAll();
} catch (PDOException $e) {
    $error = "Error fetching items: " . $e->getMessage();
}

// Fetch buy requests with pagination
$requests = [];
$total_requests = 0;
try {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM buy_requests WHERE user_id = :user_id");
    $stmt->execute([':user_id' => $_SESSION['user_id']]);
    $total_requests = $stmt->fetchColumn();
    
    $stmt = $pdo->prepare("SELECT br.*, u.username 
        FROM buy_requests br 
        JOIN users u ON br.user_id = u.id 
        WHERE br.user_id = :user_id 
        ORDER BY br.created_at DESC 
        LIMIT :limit OFFSET :offset");
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
    $stmt = $pdo->prepare("SELECT COUNT(*) 
        FROM transactions t 
        LEFT JOIN items i ON t.item_id = i.id 
        LEFT JOIN buy_requests br ON t.request_id = br.id 
        WHERE (i.posted_by = :user_id1 OR br.user_id = :user_id2)");
    $stmt->bindValue(':user_id1', $_SESSION['user_id'], PDO::PARAM_INT);
    $stmt->bindValue(':user_id2', $_SESSION['user_id'], PDO::PARAM_INT);
    $stmt->execute();
    $total_transactions = $stmt->fetchColumn();

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

// Handle GET requests for getting item data
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'get_item') {
    $item_id = intval($_GET['item_id']);
    $item_type = $_GET['item_type'];
    
    try {
        if ($item_type === 'sell') {
            $stmt = $pdo->prepare("SELECT * FROM items WHERE id = ?");
        } else {
            $stmt = $pdo->prepare("SELECT * FROM buy_requests WHERE id = ?");
        }
        $stmt->execute([$item_id]);
        $item = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($item) {
            header('Content-Type: application/json');
            echo json_encode($item);
            exit;
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
        exit;
    }
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
    <style>
        /* Custom styles for the tag input system */
        .tag-container {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            padding: 10px;
            border: 1px solid #ced4da;
            border-radius: 8px;
            background: #fff;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            min-height: 40px;
            margin-bottom: 10px;
        }

        .tag {
            display: inline-flex;
            align-items: center;
            background-color: #e9ecef;
            color: #2c3e50;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 14px;
            margin: 2px;
        }

        .tag .remove-tag {
            margin-left: 8px;
            cursor: pointer;
            color: #e74c3c;
            font-weight: bold;
            transition: color 0.2s ease;
        }

        .tag .remove-tag:hover {
            color: #c0392b;
        }

        .tag-input-wrapper {
            display: flex;
            align-items: center;
            gap: 10px;
            width: 100%;
        }

        .tag-input {
            flex-grow: 1;
            border: none;
            outline: none;
            padding: 10px;
            font-size: 14px;
            color: #2c3e50;
            background: transparent;
        }

        .add-tag-btn {
            background-color: #48dbfb;
            color: white;
            border: none;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        .add-tag-btn:hover {
            background-color: #1dc4e9;
        }

        .tag-input:focus {
            outline: none;
        }

        .error-text {
            color: #e74c3c;
            font-size: 12px;
            margin-top: -5px;
            margin-bottom: 10px;
            display: none;
        }

        .edit-form-container {
            display: none;
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            z-index: 100;
        }

        .edit-form-container.active {
            display: block;
        }

        .item-card {
            position: relative;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            padding: 20px;
            margin-bottom: 20px;
        }

        .item-card.closed {
            background: #fff5f5;
            border: 1px solid #ffcdd2;
        }

        .card-content {
            transition: opacity 0.3s ease;
        }

        .card-content.hidden {
            opacity: 0;
            pointer-events: none;
        }

        .alert {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 25px;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            z-index: 1000;
            animation: slideIn 0.3s ease-out;
        }

        .alert-success {
            background-color: #2ecc71;
        }

        .alert-error {
            background-color: #e74c3c;
        }

        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }

        .overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.5);
            z-index: 999;
        }

        .overlay.active {
            display: block;
        }

        .edit-form-container {
            display: none;
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
            z-index: 1000;
            width: 90%;
            max-width: 600px;
            max-height: 90vh;
            overflow-y: auto;
        }

        .edit-form-container.active {
            display: block;
        }

        .countdown-timer {
            background: #f8f9fa;
            padding: 8px 12px;
            border-radius: 6px;
            font-weight: 600;
            color: #333;
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }

        .countdown-timer.closing-soon {
            background: #fff3cd;
            color: #856404;
        }

        .countdown-timer.closed {
            background: #f8d7da;
            color: #721c24;
        }

        .alert {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 25px;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            z-index: 1000;
            animation: slideIn 0.3s ease-out;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .alert-success {
            background-color: #28a745;
        }

        .alert-error {
            background-color: #dc3545;
        }

        .items-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 20px;
            padding: 20px 0;
        }

        .item-card {
            border: 1px solid #e0e0e0;
            overflow: hidden;
            transition: transform 0.2s;
        }

        .item-card:hover {
            transform: translateY(-5px);
        }

        .card-image {
            width: 100%;
            height: 150px;
            overflow: hidden;
            position: relative;
        }

        .card-image img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }

        .card-status {
            position: absolute;
            top: 10px;
            right: 10px;
            background: #dc3545;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 12px;
        }

        .card-info {
            padding: 15px;
        }

        .info-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 14px;
        }

        .info-label {
            font-weight: 600;
            color: #555;
        }

        .info-value {
            color: #333;
        }

        .card-actions {
            padding: 10px 15px;
            border-top: 1px solid #e0e0e0;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .admin-btn {
            padding: 8px 15px;
            border-radius: 5px;
            text-decoration: none;
            font-size: 14px;
            transition: background-color 0.3s;
            cursor: pointer;
            border: none;
        }

        .admin-btn.primary {
            background-color: #007bff;
            color: white;
        }

        .admin-btn.primary:hover {
            background-color: #0056b3;
        }

        .admin-btn.danger {
            background-color: #dc3545;
            color: white;
        }

        .admin-btn.danger:hover {
            background-color: #b02a37;
        }

        .admin-btn.warning {
            background-color: #ffc107;
            color: #212529;
        }

        .admin-btn.warning:hover {
            background-color: #e0a800;
        }

        .admin-btn.success {
            background-color: #28a745;
            color: white;
        }

        .admin-btn.success:hover {
            background-color: #218838;
        }

        .pagination {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 20px;
        }

        .pagination-links {
            display: flex;
            gap: 10px;
            align-items: center;
        }

        .admin-btn.small {
            padding: 5px 10px;
            font-size: 12px;
        }

        .no-items {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            margin-top: 20px;
        }

        .section-title {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .section-title h2 {
            margin: 0;
            font-size: 24px;
            color: #2c3e50;
        }
    </style>
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
            <li><a href="../logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <?php if (isset($error)): ?>
            <div class="alert alert-error">
                <p><i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
            </div>
        <?php endif; ?>
        
        <?php if (isset($success)): ?>
            <div class="alert alert-success">
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
            <div class="form-card" style="background: #f8f9fa; padding: 25px; border-radius: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: #2c3e50; margin-bottom: 25px; text-align: center; font-size: 24px;"><i class="fas fa-tag"></i> Post Item for Sale</h2>
                <form method="POST" enctype="multipart/form-data" style="max-width: 700px; margin: 0 auto;" onsubmit="return updateHiddenTags('item-types-sell')">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Supplier Name</label>
                        <input type="text" name="supplier_name" class="input" placeholder="Enter supplier name" required 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Item Name</label>
                        <input type="text" name="item_name" class="input" placeholder="Enter item name" required 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Item Types (e.g., computer chair, marker)</label>
                        <div class="tag-container" id="tag-container-sell">
                            <div class="tag-input-wrapper">
                                <input type="text" id="tag-input-sell" class="tag-input" placeholder="Type and press Enter or click + to add a type">
                                <button type="button" id="add-tag-sell" class="add-tag-btn">+</button>
                            </div>
                            <div id="tag-error-sell" class="error-text" style="display: none;"></div>
                        </div>
                        <input type="hidden" name="item_types" id="item-types-sell">
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Description</label>
                        <textarea name="description" class="input" placeholder="Enter item description" rows="4" required 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;"></textarea>
                    </div>
                    
                    <div class="form-row" style="display: flex; gap: 15px; margin-bottom: 15px;">
                        <div class="form-group" style="flex: 1;">
                            <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Price ($)</label>
                            <input type="number" name="price" class="input" placeholder="Enter price" step="0.01" required 
                                style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                        </div>
                        
                        <div class="form-group" style="flex: 1;">
                            <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Quantity</label>
                            <input type="number" name="quantity" class="input" placeholder="Enter quantity" required 
                                style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                        </div>
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Close Time (optional)</label>
                        <input type="datetime-local" name="close_time" id="close_time" class="input" 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 20px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Upload Image (optional)</label>
                        <input type="file" name="image" id="item_image" class="input" accept="image/*" 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <button type="submit" class="admin-btn" 
                        style="width: 100%; padding: 12px; background:                        #28a745; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 500; cursor: pointer; transition: background-color 0.3s ease;">
                        <i class="fas fa-upload"></i> Post Item for Sale
                    </button>
                </form>
            </div>

        <?php elseif ($_GET['action'] == 'post_buy'): ?>
            <!-- Post Buy Item Form -->
            <div class="form-card" style="background: #f8f9fa; padding: 25px; border-radius: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: #2c3e50; margin-bottom: 25px; text-align: center; font-size: 24px;"><i class="fas fa-shopping-cart"></i> Post Buy Request</h2>
                <form method="POST" enctype="multipart/form-data" style="max-width: 700px; margin: 0 auto;" onsubmit="return updateHiddenTags('item-types-buy')">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Item Name</label>
                        <input type="text" name="item_name" class="input" placeholder="Enter item name" required 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Item Types (e.g., computer chair, marker)</label>
                        <div class="tag-container" id="tag-container-buy">
                            <div class="tag-input-wrapper">
                                <input type="text" id="tag-input-buy" class="tag-input" placeholder="Type and press Enter or click + to add a type">
                                <button type="button" id="add-tag-buy" class="add-tag-btn">+</button>
                            </div>
                            <div id="tag-error-buy" class="error-text" style="display: none;"></div>
                        </div>
                        <input type="hidden" name="item_types" id="item-types-buy">
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Description</label>
                        <textarea name="description" class="input" placeholder="Enter item description" rows="4" required 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;"></textarea>
                    </div>
                    
                    <div class="form-row" style="display: flex; gap: 15px; margin-bottom: 15px;">
                        <div class="form-group" style="flex: 1;">
                            <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Max Price ($)</label>
                            <input type="number" name="max_price" class="input" placeholder="Enter max price" step="0.01" required 
                                style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                        </div>
                        
                        <div class="form-group" style="flex: 1;">
                            <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Quantity</label>
                            <input type="number" name="quantity" class="input" placeholder="Enter quantity" required 
                                style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                        </div>
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Close Time (optional)</label>
                        <input type="datetime-local" name="close_time" class="input" 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 20px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Upload Image (optional)</label>
                        <input type="file" name="image" class="input" accept="image/*" 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <button type="submit" class="admin-btn" 
                        style="width: 100%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 500; cursor: pointer; transition: background-color 0.3s ease;">
                        <i class="fas fa-upload"></i> Post Buy Request
                    </button>
                </form>
            </div>

        <?php elseif ($_GET['action'] == 'items_for_sell'): ?>
            <!-- Items for Sale -->
            <div class="section-title">
                <h2><i class="fas fa-box-open"></i> Items for Sale</h2>
                <a href="?action=post_sell" class="admin-btn primary"><i class="fas fa-plus"></i> Add New Item</a>
            </div>
            
            <?php if (empty($items)): ?>
                <div class="no-items">
                    <p>No items for sale. <a href="?action=post_sell">Add a new item</a>.</p>
                </div>
            <?php else: ?>
                <div class="items-grid">
                    <?php foreach ($items as $item): ?>
                        <div class="item-card <?php echo $item['status'] == 'closed' ? 'closed' : ''; ?>" data-item-id="<?php echo htmlspecialchars($item['id'], ENT_QUOTES, 'UTF-8'); ?>">
                            <div class="card-content">
                                <?php if ($item['image']): ?>
                                    <div class="card-image">
                                        <img src="../<?php echo htmlspecialchars($item['image'], ENT_QUOTES, 'UTF-8'); ?>" alt="Item Image">
                                        <span class="card-status"><?php echo htmlspecialchars($item['status'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                <?php endif; ?>
                                
                                <div class="card-info">
                                    <div class="info-row">
                                        <span class="info-label">Item Name:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($item['item_name'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Supplier:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($item['supplier_name'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Price:</span>
                                        <span class="info-value">$<?php echo number_format($item['price'], 2); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Quantity:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($item['quantity'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                    <?php if ($item['close_time']): ?>
                                        <div class="info-row">
                                            <span class="info-label">Closes:</span>
                                            <span class="countdown-timer" data-close-time="<?php echo htmlspecialchars($item['close_time'], ENT_QUOTES, 'UTF-8'); ?>">
                                                <i class="fas fa-clock"></i> <span class="time-left"></span>
                                            </span>
                                        </div>
                                    <?php endif; ?>
                                </div>
                                
                                <div class="card-actions">
                                    <?php if ($item['status'] == 'open'): ?>
                                        <button class="admin-btn primary edit-btn" data-item-id="<?php echo htmlspecialchars($item['id'], ENT_QUOTES, 'UTF-8'); ?>" data-item-type="sell">
                                            <i class="fas fa-edit"></i> Edit
                                        </button>
                                        <a href="?action=close_item&item_id=<?php echo htmlspecialchars($item['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn warning">
                                            <i class="fas fa-times"></i> Close
                                        </a>
                                    <?php endif; ?>
                                    <a href="?action=delete_item&item_id=<?php echo htmlspecialchars($item['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this item and all related offers/transactions?');">
                                        <i class="fas fa-trash"></i> Delete
                                    </a>
                                </div>
                            </div>
                            <div class="edit-form-container" id="edit-form-<?php echo htmlspecialchars($item['id'], ENT_QUOTES, 'UTF-8'); ?>"></div>
                        </div>
                    <?php endforeach; ?>
                </div>
                
                <!-- Pagination -->
                <?php
                $total_pages = ceil($total_items / $items_per_page);
                if ($total_pages > 1):
                ?>
                    <div class="pagination">
                        <div class="pagination-links">
                            <?php if ($page > 1): ?>
                                <a href="?action=items_for_sell&page=<?php echo $page - 1; ?>" class="admin-btn small"><i class="fas fa-chevron-left"></i> Previous</a>
                            <?php endif; ?>
                            
                            <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                                <a href="?action=items_for_sell&page=<?php echo $i; ?>" class="admin-btn small <?php echo $i == $page ? 'primary' : ''; ?>"><?php echo $i; ?></a>
                            <?php endfor; ?>
                            
                            <?php if ($page < $total_pages): ?>
                                <a href="?action=items_for_sell&page=<?php echo $page + 1; ?>" class="admin-btn small">Next <i class="fas fa-chevron-right"></i></a>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'buy_requests'): ?>
            <!-- Active Buy Requests -->
            <div class="section-title">
                <h2><i class="fas fa-hand-holding-usd"></i> Active Buy Requests</h2>
                <a href="?action=post_buy" class="admin-btn primary"><i class="fas fa-plus"></i> Create Buy Request</a>
            </div>
            
            <?php if (empty($requests)): ?>
                <div class="no-items">
                    <p>No active buy requests. <a href="?action=post_buy">Create a new buy request</a>.</p>
                </div>
            <?php else: ?>
                <div class="items-grid">
                    <?php foreach ($requests as $request): ?>
                        <div class="item-card <?php echo $request['status'] == 'closed' ? 'closed' : ''; ?>" data-item-id="<?php echo htmlspecialchars($request['id'], ENT_QUOTES, 'UTF-8'); ?>">
                            <div class="card-content">
                                <?php if ($request['image']): ?>
                                    <div class="card-image">
                                        <img src="../<?php echo htmlspecialchars($request['image'], ENT_QUOTES, 'UTF-8'); ?>" alt="Request Image">
                                        <span class="card-status"><?php echo htmlspecialchars($request['status'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                <?php endif; ?>
                                
                                <div class="card-info">
                                    <div class="info-row">
                                        <span class="info-label">Item Name:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($request['item_name'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Max Price:</span>
                                        <span class="info-value">$<?php echo number_format($request['max_price'], 2); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Quantity:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($request['quantity'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                    <?php if ($request['close_time']): ?>
                                        <div class="info-row">
                                            <span class="info-label">Closes:</span>
                                            <span class="countdown-timer" data-close-time="<?php echo htmlspecialchars($request['close_time'], ENT_QUOTES, 'UTF-8'); ?>">
                                                <i class="fas fa-clock"></i> <span class="time-left"></span>
                                            </span>
                                        </div>
                                    <?php endif; ?>
                                </div>
                                
                                <div class="card-actions">
                                    <?php if ($request['status'] == 'open'): ?>
                                        <button class="admin-btn primary edit-btn" data-item-id="<?php echo htmlspecialchars($request['id'], ENT_QUOTES, 'UTF-8'); ?>" data-item-type="buy">
                                            <i class="fas fa-edit"></i> Edit
                                        </button>
                                        <a href="?action=close_buy_request&request_id=<?php echo htmlspecialchars($request['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn warning">
                                            <i class="fas fa-times"></i> Close
                                        </a>
                                        <a href="?action=view_offers&request_id=<?php echo htmlspecialchars($request['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn success">
                                            <i class="fas fa-exchange-alt"></i> View Offers
                                        </a>
                                    <?php endif; ?>
                                    <a href="?action=delete_buy_request&request_id=<?php echo htmlspecialchars($request['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this buy request and all related offers/transactions?');">
                                        <i class="fas fa-trash"></i> Delete
                                    </a>
                                </div>
                            </div>
                            <div class="edit-form-container" id="edit-form-<?php echo htmlspecialchars($request['id'], ENT_QUOTES, 'UTF-8'); ?>"></div>
                        </div>
                    <?php endforeach; ?>
                </div>
                
                <!-- Pagination -->
                <?php
                $total_pages = ceil($total_requests / $items_per_page);
                if ($total_pages > 1):
                ?>
                    <div class="pagination">
                        <div class="pagination-links">
                            <?php if ($page > 1): ?>
                                <a href="?action=buy_requests&page=<?php echo $page - 1; ?>" class="admin-btn small"><i class="fas fa-chevron-left"></i> Previous</a>
                            <?php endif; ?>
                            
                            <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                                <a href="?action=buy_requests&page=<?php echo $i; ?>" class="admin-btn small <?php echo $i == $page ? 'primary' : ''; ?>"><?php echo $i; ?></a>
                            <?php endfor; ?>
                            
                            <?php if ($page < $total_pages): ?>
                                <a href="?action=buy_requests&page=<?php echo $page + 1; ?>" class="admin-btn small">Next <i class="fas fa-chevron-right"></i></a>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'view_offers' && isset($_GET['request_id'])): ?>
            <!-- View Offers for Buy Request -->
            <h2><i class="fas fa-exchange-alt"></i> Offers for Buy Request</h2>
            
            <?php if (empty($buy_request_offers)): ?>
                <div class="no-items">
                    <p>No offers available for this buy request.</p>
                </div>
            <?php else: ?>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Item Name</th>
                            <th>Offered By</th>
                            <th>Price</th>
                            <th>Quantity</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($buy_request_offers as $offer): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($offer['item_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars($offer['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>$<?php echo number_format($offer['offered_price'], 2); ?></td>
                                <td><?php echo htmlspecialchars($offer['quantity'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars($offer['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>
                                    <a href="?action=offer_action&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>&type=accept" class="admin-btn success">
                                        <i class="fas fa-check"></i> Accept
                                    </a>
                                    <a href="?action=offer_action&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>&type=reject" class="admin-btn danger">
                                        <i class="fas fa-times"></i> Reject
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
            <a href="?action=buy_requests" class="admin-btn primary"><i class="fas fa-arrow-left"></i> Back to Buy Requests</a>

        <?php elseif ($_GET['action'] == 'offers'): ?>
            <!-- Offers Section -->
            <h2><i class="fas fa-exchange-alt"></i> Offers</h2>
            
            <!-- Buy Offers -->
            <h3>Offers on Your Items for Sale</h3>
            <?php if (empty($buy_offers)): ?>
                <div class="no-items">
                    <p>No pending offers on your items for sale.</p>
                </div>
            <?php else: ?>
                <div class="sort-controls" style="margin-bottom: 20px;">
                    <form method="GET">
                        <input type="hidden" name="action" value="offers">
                        <label style="margin-right: 10px;">Sort By:</label>
                        <select name="buy_sort_field" style="padding: 5px; border-radius: 5px; margin-right: 10px;">
                            <option value="offered_price" <?php echo $buy_sort_field == 'offered_price' ? 'selected' : ''; ?>>Price</option>
                            <option value="created_at" <?php echo $buy_sort_field == 'created_at' ? 'selected' : ''; ?>>Date</option>
                        </select>
                        <select name="buy_sort_order" style="padding: 5px; border-radius: 5px; margin-right: 10px;">
                            <option value="ASC" <?php echo $buy_sort_order == 'ASC' ? 'selected' : ''; ?>>Ascending</option>
                            <option value="DESC" <?php echo $buy_sort_order == 'DESC' ? 'selected' : ''; ?>>Descending</option>
                        </select>
                        <button type="submit" class="admin-btn primary small">Sort</button>
                    </form>
                </div>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Item Name</th>
                            <th>Offered By</th>
                            <th>Price</th>
                            <th>Quantity</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($buy_offers as $offer): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($offer['item_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars($offer['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>$<?php echo number_format($offer['offered_price'], 2); ?></td>
                                <td><?php echo htmlspecialchars($offer['quantity'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars($offer['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>
                                    <a href="?action=offer_action&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>&type=accept" class="admin-btn success">
                                        <i class="fas fa-check"></i> Accept
                                    </a>
                                    <a href="?action=offer_action&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>&type=reject" class="admin-btn danger">
                                        <i class="fas fa-times"></i> Reject
                                    </a>
                                    <a href="?action=close_offer&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn warning">
                                        <i class="fas fa-ban"></i> Close
                                    </a>
                                    <a href="?action=delete_offer&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this offer?');">
                                        <i class="fas fa-trash"></i> Delete
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
            
            <!-- Sell Offers -->
            <h3>Offers on Your Buy Requests</h3>
            <?php if (empty($sell_offers)): ?>
                <div class="no-items">
                    <p>No pending offers on your buy requests.</p>
                </div>
            <?php else: ?>
                <div class="sort-controls" style="margin-bottom: 20px;">
                    <form method="GET">
                        <input type="hidden" name="action" value="offers">
                        <label style="margin-right: 10px;">Sort By:</label>
                        <select name="sell_sort_field" style="padding: 5px; border-radius: 5px; margin-right: 10px;">
                            <option value="offered_price" <?php echo $sell_sort_field == 'offered_price' ? 'selected' : ''; ?>>Price</option>
                            <option value="created_at" <?php echo $sell_sort_field == 'created_at' ? 'selected' : ''; ?>>Date</option>
                        </select>
                        <select name="sell_sort_order" style="padding: 5px; border-radius: 5px; margin-right: 10px;">
                            <option value="ASC" <?php echo $sell_sort_order == 'ASC' ? 'selected' : ''; ?>>Ascending</option>
                            <option value="DESC" <?php echo $sell_sort_order == 'DESC' ? 'selected' : ''; ?>>Descending</option>
                        </select>
                        <button type="submit" class="admin-btn primary small">Sort</button>
                    </form>
                </div>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Item Name</th>
                            <th>Offered By</th>
                            <th>Price</th>
                            <th>Quantity</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($sell_offers as $offer): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($offer['item_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars($offer['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>$<?php echo number_format($offer['offered_price'], 2); ?></td>
                                <td><?php echo htmlspecialchars($offer['quantity'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars($offer['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>
                                    <a href="?action=offer_action&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>&type=accept" class="admin-btn success">
                                        <i class="fas fa-check"></i> Accept
                                    </a>
                                    <a href="?action=offer_action&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>&type=reject" class="admin-btn danger">
                                        <i class="fas fa-times"></i> Reject
                                    </a>
                                    <a href="?action=close_offer&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn warning">
                                        <i class="fas fa-ban"></i> Close
                                    </a>
                                    <a href="?action=delete_offer&offer_id=<?php echo htmlspecialchars($offer['id'], ENT_QUOTES, 'UTF-8'); ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this offer?');">
                                        <i class="fas fa-trash"></i> Delete
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'transactions'): ?>
            <!-- Transactions -->
            <h2><i class="fas fa-receipt"></i> Transactions</h2>
            
            <?php if (empty($transactions)): ?>
                <div class="no-items">
                    <p>No transactions found.</p>
                </div>
            <?php else: ?>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Item Name</th>
                            <th>Type</th>
                            <th>Buyer</th>
                            <th>Seller</th>
                            <th>Final Price</th>
                            <th>Quantity</th>
                            <th>Total Amount</th>
                            <th>Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($transactions as $t): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($t['item_name_sell'] ?? $t['item_name_buy'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo $t['item_id'] ? 'Sell' : 'Buy'; ?></td>
                                <td><?php echo htmlspecialchars($t['buyer'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars($t['seller'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>$<?php echo number_format($t['final_price'], 2); ?></td>
                                <td><?php echo htmlspecialchars($t['quantity'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>$<?php echo number_format($t['final_price'] * $t['quantity'], 2); ?></td>
                                <td><?php echo htmlspecialchars($t['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                
                <!-- Pagination -->
                <?php
                $total_pages = ceil($total_transactions / $items_per_page);
                if ($total_pages > 1):
                ?>
                    <div class="pagination">
                        <div class="pagination-links">
                            <?php if ($page > 1): ?>
                                <a href="?action=transactions&page=<?php echo $page - 1; ?>" class="admin-btn small"><i class="fas fa-chevron-left"></i> Previous</a>
                            <?php endif; ?>
                            
                            <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                                <a href="?action=transactions&page=<?php echo $i; ?>" class="admin-btn small <?php echo $i == $page ? 'primary' : ''; ?>"><?php echo $i; ?></a>
                            <?php endfor; ?>
                            
                            <?php if ($page < $total_pages): ?>
                                <a href="?action=transactions&page=<?php echo $page + 1; ?>" class="admin-btn small">Next <i class="fas fa-chevron-right"></i></a>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'report'): ?>
            <!-- Reports -->
            <h2><i class="fas fa-chart-pie"></i> Generate Report</h2>
            <div class="form-card">
                <form method="POST" action="?action=report&generate_report=1">
                    <div class="form-row">
                        <div class="form-group">
                            <label>Start Date</label>
                            <input type="date" name="start_date" class="input">
                        </div>
                        <div class="form-group">
                            <label>End Date</label>
                            <input type="date" name="end_date" class="input">
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Transaction Type</label>
                            <select name="transaction_type" class="input">
                                <option value="all">All</option>
                                <option value="sell">Sell Transactions</option>
                                <option value="buy">Buy Transactions</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Status</label>
                            <select name="status" class="input">
                                <option value="all">All</option>
                                <option value="open">Open</option>
                                <option value="closed">Closed</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-row">
                        <button type="submit" name="generate_report" class="admin-btn primary">
                            <i class="fas fa-eye"></i> Generate Report
                        </button>
                        <button type="submit" name="export_csv" class="admin-btn success">
                            <i class="fas fa-download"></i> Export to CSV
                        </button>
                    </div>
                </form>
            </div>
            
            <?php if (isset($report_transactions)): ?>
                <h3>Transactions Report</h3>
                <?php if (empty($report_transactions)): ?>
                    <div class="no-items">
                        <p>No transactions found for the selected criteria.</p>
                    </div>
                <?php else: ?>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Item Name</th>
                                <th>Type</th>
                                <th>Buyer</th>
                                <th>Seller</th>
                                <th>Supplier</th>
                                <th>Original Price/Max Price</th>
                                <th>Final Price</th>
                                <th>Quantity</th>
                                <th>Total Amount</th>
                                <th>Description</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($report_transactions as $t): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($t['item_name_sell'] ?? $t['item_name_buy'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo $t['item_id'] ? 'Sell' : 'Buy'; ?></td>
                                    <td><?php echo htmlspecialchars($t['buyer'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($t['seller'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($t['supplier_name_sell'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td>$<?php echo number_format($t['item_id'] ? ($t['original_price_sell'] ?? 0) : ($t['max_price_buy'] ?? 0), 2); ?></td>
                                    <td>$<?php echo number_format($t['final_price'], 2); ?></td>
                                    <td><?php echo htmlspecialchars($t['quantity'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td>$<?php echo number_format($t['final_price'] * $t['quantity'], 2); ?></td>
                                    <td><?php echo htmlspecialchars($t['description_sell'] ?? $t['description_buy'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($t['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
                
                <h3>Inventory Report</h3>
                <?php if (empty($report_items)): ?>
                    <div class="no-items">
                        <p>No items found for the selected criteria.</p>
                    </div>
                <?php else: ?>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Item Name</th>
                                <th>Supplier</th>
                                <th>Description</th>
                                <th>Price</th>
                                <th>Quantity</th>
                                <th>Status</th>
                                <th>Posted By</th>
                                <th>Created At</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($report_items as $item): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($item['item_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($item['supplier_name'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($item['description'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td>$<?php echo number_format($item['price'], 2); ?></td>
                                    <td><?php echo htmlspecialchars($item['quantity'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($item['status'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($item['posted_by_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($item['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
                
                <h3>Buy Requests Report</h3>
                <?php if (empty($report_requests)): ?>
                    <div class="no-items">
                        <p>No buy requests found for the selected criteria.</p>
                    </div>
                <?php else: ?>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Item Name</th>
                                <th>Description</th>
                                <th>Max Price</th>
                                <th>Quantity</th>
                                <th>Status</th>
                                <th>User</th>
                                <th>Created At</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($report_requests as $request): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($request['item_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($request['description'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td>$<?php echo number_format($request['max_price'], 2); ?></td>
                                    <td><?php echo htmlspecialchars($request['quantity'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($request['status'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($request['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($request['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            <?php endif; ?>

        <?php endif; ?>
    </div>
</div>

<!-- Overlay for Edit Forms -->
<div class="overlay" id="overlay"></div>

<!-- Footer -->
<footer class="footer">
    <div class="inner-width">
        <p>&copy; <?php echo date('Y'); ?> Online Bidding System | All Rights Reserved</p>
    </div>
</footer>

<script>
// Tag Input System for Sell Form
let tagsSell = [];
const tagContainerSell = document.getElementById('tag-container-sell');
const tagInputSell = document.getElementById('tag-input-sell');
const addTagButtonSell = document.getElementById('add-tag-sell');
const tagErrorSell = document.getElementById('tag-error-sell');

function renderTagsSell() {
    const tagWrapperSell = tagContainerSell.querySelector('.tag-input-wrapper');
    const existingTagsSell = tagContainerSell.querySelectorAll('.tag');
    existingTagsSell.forEach(tag => tag.remove());

    tagsSell.forEach((tag, index) => {
        const tagElement = document.createElement('span');
        tagElement.className = 'tag';
        tagElement.innerHTML = `
            ${tag}
            <span class="remove-tag" data-index="${index}">&times;</span>
        `;
        tagContainerSell.insertBefore(tagElement, tagWrapperSell);
    });

    tagErrorSell.style.display = tagsSell.length === 0 ? 'block' : 'none';
    tagErrorSell.textContent = tagsSell.length === 0 ? 'At least one item type is required.' : '';
}

function addTagSell(tag) {
    tag = tag.trim();
    if (tag && !tagsSell.includes(tag)) {
        tagsSell.push(tag);
        renderTagsSell();
    }
    tagInputSell.value = '';
}

tagInputSell.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        addTagSell(tagInputSell.value);
    }
});

addTagButtonSell.addEventListener('click', () => {
    addTagSell(tagInputSell.value);
});

tagContainerSell.addEventListener('click', (e) => {
    if (e.target.classList.contains('remove-tag')) {
        const index = e.target.getAttribute('data-index');
        tagsSell.splice(index, 1);
        renderTagsSell();
    }
});

// Tag Input System for Buy Form
let tagsBuy = [];
const tagContainerBuy = document.getElementById('tag-container-buy');
const tagInputBuy = document.getElementById('tag-input-buy');
const addTagButtonBuy = document.getElementById('add-tag-buy');
const tagErrorBuy = document.getElementById('tag-error-buy');

function renderTagsBuy() {
    const tagWrapperBuy = tagContainerBuy.querySelector('.tag-input-wrapper');
    const existingTagsBuy = tagContainerBuy.querySelectorAll('.tag');
    existingTagsBuy.forEach(tag => tag.remove());

    tagsBuy.forEach((tag, index) => {
        const tagElement = document.createElement('span');
        tagElement.className = 'tag';
        tagElement.innerHTML = `
            ${tag}
            <span class="remove-tag" data-index="${index}">&times;</span>
        `;
        tagContainerBuy.insertBefore(tagElement, tagWrapperBuy);
    });

    tagErrorBuy.style.display = tagsBuy.length === 0 ? 'block' : 'none';
    tagErrorBuy.textContent = tagsBuy.length === 0 ? 'At least one item type is required.' : '';
}

function addTagBuy(tag) {
    tag = tag.trim();
    if (tag && !tagsBuy.includes(tag)) {
        tagsBuy.push(tag);
        renderTagsBuy();
    }
    tagInputBuy.value = '';
}

tagInputBuy.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        addTagBuy(tagInputBuy.value);
    }
});

addTagButtonBuy.addEventListener('click', () => {
    addTagBuy(tagInputBuy.value);
});

tagContainerBuy.addEventListener('click', (e) => {
    if (e.target.classList.contains('remove-tag')) {
        const index = e.target.getAttribute('data-index');
        tagsBuy.splice(index, 1);
        renderTagsBuy();
    }
});

function updateHiddenTags(containerId) {
    const hiddenInput = document.getElementById(containerId);
    if (containerId === 'item-types-sell') {
        hiddenInput.value = tagsSell.join(',');
        if (tagsSell.length === 0) {
            tagErrorSell.style.display = 'block';
            tagErrorSell.textContent = 'At least one item type is required.';
            return false;
        }
    } else if (containerId === 'item-types-buy') {
        hiddenInput.value = tagsBuy.join(',');
        if (tagsBuy.length === 0) {
            tagErrorBuy.style.display = 'block';
            tagErrorBuy.textContent = 'At least one item type is required.';
            return false;
        }
    }
    return true;
}

// Countdown Timer for Close Time
function updateCountdownTimers() {
    document.querySelectorAll('.countdown-timer').forEach(timer => {
        const closeTime = new Date(timer.getAttribute('data-close-time')).getTime();
        const now = new Date().getTime();
        const timeLeft = closeTime - now;

        const timeLeftElement = timer.querySelector('.time-left');
        if (timeLeft <= 0) {
            timer.classList.add('closed');
            timeLeftElement.textContent = 'Closed';
        } else {
            const days = Math.floor(timeLeft / (1000 * 60 * 60 * 24));
            const hours = Math.floor((timeLeft % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
            const minutes = Math.floor((timeLeft % (1000 * 60 * 60)) / (1000 * 60));
            const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);

            let timeString = '';
            if (days > 0) timeString += `${days}d `;
            if (hours > 0 || days > 0) timeString += `${hours}h `;
            if (minutes > 0 || hours > 0 || days > 0) timeString += `${minutes}m `;
            timeString += `${seconds}s`;

            timeLeftElement.textContent = timeString;

            if (timeLeft < 24 * 60 * 60 * 1000) {
                timer.classList.add('closing-soon');
            }
        }
    });
}

setInterval(updateCountdownTimers, 1000);
updateCountdownTimers();

// Edit Form Handling
document.querySelectorAll('.edit-btn').forEach(button => {
    button.addEventListener('click', async () => {
        const itemId = button.getAttribute('data-item-id');
        const itemType = button.getAttribute('data-item-type');
        const formContainer = document.getElementById(`edit-form-${itemId}`);
        const overlay = document.getElementById('overlay');
        const cardContent = button.closest('.item-card').querySelector('.card-content');

        try {
            const response = await fetch(`?action=get_item&item_id=${itemId}&item_type=${itemType}`);
            const item = await response.json();

            if (response.ok) {
                let formHTML = `
                    <h3>Edit ${itemType === 'sell' ? 'Item for Sale' : 'Buy Request'}</h3>
                    <form method="POST" action="?action=${itemType === 'sell' ? 'edit_item' : 'edit_buy_request'}&${itemType === 'sell' ? 'item_id' : 'request_id'}=${itemId}" enctype="multipart/form-data" onsubmit="return updateHiddenTags('edit-item-types-${itemId}')">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                        ${itemType === 'sell' ? `
                        <div class="form-group">
                            <label>Supplier Name</label>
                            <input type="text" name="supplier_name" value="${item.supplier_name || ''}" class="input" required>
                        </div>` : ''}
                        <div class="form-group">
                            <label>Item Name</label>
                            <input type="text" name="item_name" value="${item.item_name}" class="input" required>
                        </div>
                        <div class="form-group">
                            <label>Item Types</label>
                            <div class="tag-container" id="edit-tag-container-${itemId}">
                                <div class="tag-input-wrapper">
                                    <input type="text" id="edit-tag-input-${itemId}" class="tag-input" placeholder="Type and press Enter or click + to add a type">
                                    <button type="button" id="edit-add-tag-${itemId}" class="add-tag-btn">+</button>
                                </div>
                                <div id="edit-tag-error-${itemId}" class="error-text" style="display: none;"></div>
                            </div>
                            <input type="hidden" name="item_types" id="edit-item-types-${itemId}">
                        </div>
                        <div class="form-group">
                            <label>Description</label>
                            <textarea name="description" class="input" required>${item.description}</textarea>
                        </div>
                        <div class="form-group">
                            <label>${itemType === 'sell' ? 'Price' : 'Max Price'} ($)</label>
                            <input type="number" name="${itemType === 'sell' ? 'price' : 'max_price'}" value="${itemType === 'sell' ? item.price : item.max_price}" class="input" step="0.01" required>
                        </div>
                        <div class="form-group">
                            <label>Quantity</label>
                            <input type="number" name="quantity" value="${item.quantity}" class="input" required>
                        </div>
                        <div class="form-group">
                            <label>Close Time (optional)</label>
                            <input type="datetime-local" name="close_time" value="${item.close_time ? item.close_time.replace(' ', 'T').slice(0, 16) : ''}" class="input">
                        </div>
                        <div class="form-group">
                            <label>Current Image</label>
                            ${item.image ? `<img src="../${item.image}" alt="Current Image" style="max-width: 100px;"><br>` : 'No image uploaded.<br>'}
                            <label>Upload New Image (optional)</label>
                            <input type="file" name="image" class="input" accept="image/*">
                            <input type="hidden" name="existing_image" value="${item.image || ''}">
                        </div>
                        <div class="form-row">
                            <button type="submit" class="admin-btn primary"><i class="fas fa-save"></i> Save Changes</button>
                            <button type="button" class="admin-btn danger cancel-btn"><i class="fas fa-times"></i> Cancel</button>
                        </div>
                    </form>
                `;

                formContainer.innerHTML = formHTML;
                formContainer.classList.add('active');
                overlay.classList.add('active');
                cardContent.classList.add('hidden');

                // Initialize tags for edit form
                let editTags = item.item_type ? item.item_type.split(',').map(tag => tag.trim()) : [];
                const editTagContainer = document.getElementById(`edit-tag-container-${itemId}`);
                const editTagInput = document.getElementById(`edit-tag-input-${itemId}`);
                const editAddTagButton = document.getElementById(`edit-add-tag-${itemId}`);
                const editTagError = document.getElementById(`edit-tag-error-${itemId}`);

                function renderEditTags() {
                    const tagWrapper = editTagContainer.querySelector('.tag-input-wrapper');
                    const existingTags = editTagContainer.querySelectorAll('.tag');
                    existingTags.forEach(tag => tag.remove());

                    editTags.forEach((tag, index) => {
                        const tagElement = document.createElement('span');
                        tagElement.className = 'tag';
                        tagElement.innerHTML = `
                            ${tag}
                            <span class="remove-tag" data-index="${index}">&times;</span>
                        `;
                        editTagContainer.insertBefore(tagElement, tagWrapper);
                    });

                    editTagError.style.display = editTags.length === 0 ? 'block' : 'none';
                    editTagError.textContent = editTags.length === 0 ? 'At least one item type is required.' : '';
                }

                function addEditTag(tag) {
                    tag = tag.trim();
                    if (tag && !editTags.includes(tag)) {
                        editTags.push(tag);
                        renderEditTags();
                    }
                    editTagInput.value = '';
                }

                editTagInput.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        addEditTag(editTagInput.value);
                    }
                });

                editAddTagButton.addEventListener('click', () => {
                    addEditTag(editTagInput.value);
                });

                editTagContainer.addEventListener('click', (e) => {
                    if (e.target.classList.contains('remove-tag')) {
                        const index = e.target.getAttribute('data-index');
                        editTags.splice(index, 1);
                        renderEditTags();
                    }
                });

                // Set initial tags
                renderEditTags();

                // Update hidden input with tags
                document.getElementById(`edit-item-types-${itemId}`).value = editTags.join(',');

                // Cancel button functionality
                formContainer.querySelector('.cancel-btn').addEventListener('click', () => {
                    formContainer.classList.remove('active');
                    overlay.classList.remove('active');
                    cardContent.classList.remove('hidden');
                });
            } else {
                alert('Failed to load item data.');
            }
        } catch (error) {
            console.error('Error fetching item data:', error);
            alert('An error occurred while loading the item data.');
        }
    });
});

// Auto-dismiss alerts
document.querySelectorAll('.alert').forEach(alert => {
    setTimeout(() => {
        alert.style.animation = 'slideOut 0.3s ease-in forwards';
    }, 5000);
});

function slideOut() {
    return `
        @keyframes slideOut {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(100%);
                opacity: 0;
            }
        }
    `;
}

// Navbar Toggle
document.querySelector('.menu-toggler').addEventListener('click', () => {
    document.querySelector('.navbar-menu').classList.toggle('active');
});
</script>

</body>
</html>