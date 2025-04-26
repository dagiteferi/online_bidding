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

// Handle all operations at the top of the file
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $item_id = $_POST['item_id'] ?? 0;
    $item_type = $_POST['item_type'] ?? '';
    
    try {
        $pdo->beginTransaction();
        
        switch ($action) {
            case 'delete':
                // First delete related records
                if ($item_type === 'buy') {
                    $stmt = $pdo->prepare("DELETE FROM offers WHERE buy_request_id = ?");
                } else {
                    $stmt = $pdo->prepare("DELETE FROM bids WHERE item_id = ?");
                }
                $stmt->execute([$item_id]);
                
                // Then delete the item
                $stmt = $pdo->prepare("DELETE FROM items WHERE id = ?");
                $stmt->execute([$item_id]);
                $success_message = "Item deleted successfully";
                break;
                
            case 'close':
                $stmt = $pdo->prepare("UPDATE items SET status = 'closed', close_time = NOW() WHERE id = ?");
                $stmt->execute([$item_id]);
                $success_message = "Item closed successfully";
                break;
                
            case 'reopen':
                $stmt = $pdo->prepare("UPDATE items SET status = 'open', close_time = NULL WHERE id = ?");
                $stmt->execute([$item_id]);
                $success_message = "Item reopened successfully";
                break;
                
            case 'update':
                $item_name = sanitizeInput($_POST['item_name']);
                $description = sanitizeInput($_POST['description']);
                $price = floatval($_POST['price']);
                $quantity = intval($_POST['quantity']);
                $close_time = !empty($_POST['close_time']) ? $_POST['close_time'] : null;
                
                if ($item_type === 'sell') {
                    $stmt = $pdo->prepare("UPDATE items SET item_name = ?, description = ?, price = ?, quantity = ?, close_time = ? WHERE id = ?");
                } else {
                    $stmt = $pdo->prepare("UPDATE buy_requests SET item_name = ?, description = ?, max_price = ?, quantity = ?, close_time = ? WHERE id = ?");
                }
                $stmt->execute([$item_name, $description, $price, $quantity, $close_time, $item_id]);
                
                $success_message = "Item updated successfully";
                break;
                
            default:
                throw new Exception("Invalid action specified");
        }
        
        $pdo->commit();
    } catch (Exception $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        $error_message = "An error occurred: " . $e->getMessage();
    }
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

// Show success/error messages if they exist
if (isset($success_message)) {
    echo "<div class='alert alert-success'>$success_message</div>";
}
if (isset($error_message)) {
    echo "<div class='alert alert-error'>$error_message</div>";
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

        /* Add this CSS in the head section */
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
            <div class="form-card" style="background: #f8f9fa; padding: 25px; border-radius: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: #2c3e50; margin-bottom: 25px; text-align: center; font-size: 24px;"><i class="fas fa-tag"></i> Post Item for Sale</h2>
                <form method="POST" enctype="multipart/form-data" style="max-width: 700px; margin: 0 auto;" onsubmit="updateHiddenTags('item-types-sell')">
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
                        style="width: 100%; padding: 12px; background: #48dbfb; color: white; border: none; border-radius: 8px; font-size: 14px; cursor: pointer; transition: background 0.3s;">
                        <i class="fas fa-save"></i> Submit Item
                    </button>
                </form>
            </div>

        <?php elseif ($_GET['action'] == 'edit_item' && isset($item_to_edit)): ?>
            <!-- Edit Item Form -->
            <div class="form-card">
                <h2><i class="fas fa-edit"></i> Edit Item</h2>
                <form method="POST" enctype="multipart/form-data" onsubmit="updateHiddenTags('item-types-edit')">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="existing_image" value="<?php echo htmlspecialchars($item_to_edit['image'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                    <div class="form-group">
                        <label>Supplier Name:</label>
                        <input type="text" name="supplier_name" class="input" value="<?php echo htmlspecialchars($item_to_edit['supplier_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" placeholder="<?php echo htmlspecialchars($item_to_edit['supplier_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required />
                    </div>
                    <div class="form-group">
                        <label>Item Name:</label>
                        <input type="text" name="item_name" class="input" value="<?php echo htmlspecialchars($item_to_edit['item_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" placeholder="<?php echo htmlspecialchars($item_to_edit['item_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required />
                    </div>
                    <div class="form-group">
                        <label>Item Types (e.g., computer chair, marker):</label>
                        <div class="tag-container" id="tag-container-edit">
                            <div class="tag-input-wrapper">
                                <input type="text" id="tag-input-edit" class="tag-input" placeholder="Type and press Enter or click + to add a type">
                                <button type="button" id="add-tag-edit" class="add-tag-btn">+</button>
                            </div>
                            <div id="tag-error-edit" class="error-text" style="display: none;"></div>
                        </div>
                        <input type="hidden" name="item_types" id="item-types-edit" value="<?php echo htmlspecialchars($item_to_edit['item_type'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                    <div class="form-group">
                        <label>Description:</label>
                        <textarea name="description" class="input" rows="4" placeholder="<?php echo htmlspecialchars($item_to_edit['description'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required><?php echo htmlspecialchars($item_to_edit['description'] ?? '', ENT_QUOTES, 'UTF-8'); ?></textarea>
                    </div>
                    <div class="form-group">
                        <label>Price ($):</label>
                        <input type="number" name="price" class="input" value="<?php echo htmlspecialchars($item_to_edit['price'] ?? 0, ENT_QUOTES, 'UTF-8'); ?>" placeholder="<?php echo htmlspecialchars($item_to_edit['price'] ?? 0, ENT_QUOTES, 'UTF-8'); ?>" step="0.01" required />
                    </div>
                    <div class="form-group">
                        <label>Quantity:</label>
                        <input type="number" name="quantity" class="input" value="<?php echo htmlspecialchars($item_to_edit['quantity'] ?? 0, ENT_QUOTES, 'UTF-8'); ?>" placeholder="<?php echo htmlspecialchars($item_to_edit['quantity'] ?? 0, ENT_QUOTES, 'UTF-8'); ?>" required />
                    </div>
                    <div class="form-group">
                        <label>Close Time (optional):</label>
                        <input type="datetime-local" name="close_time" id="close_time" class="input" value="<?php echo !empty($item_to_edit['close_time']) && strtotime($item_to_edit['close_time']) ? date('Y-m-d\TH:i', strtotime($item_to_edit['close_time'])) : ''; ?>" placeholder="<?php echo !empty($item_to_edit['close_time']) && strtotime($item_to_edit['close_time']) ? date('Y-m-d\TH:i', strtotime($item_to_edit['close_time'])) : ''; ?>" />
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
            <div class="form-card" style="background: #f8f9fa; padding: 25px; border-radius: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: #2c3e50; margin-bottom: 25px; text-align: center; font-size: 24px;"><i class="fas fa-shopping-cart"></i> Post Buy Request</h2>
                <form method="POST" enctype="multipart/form-data" style="max-width: 700px; margin: 0 auto;" onsubmit="updateHiddenTags('item-types-buy')">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Item Name</label>
                        <input type="text" name="item_name" class="input" placeholder="Enter item name" required 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease;" />
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
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease;"></textarea>
                    </div>
                    
                    <div class="form-row" style="display: flex; gap: 15px; margin-bottom: 15px;">
                        <div class="form-group" style="flex: 1;">
                            <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Maximum Price ($)</label>
                            <input type="number" name="max_price" class="input" placeholder="Enter maximum price" step="0.01" required 
                                style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease;" />
                        </div>
                        
                        <div class="form-group" style="flex: 1;">
                            <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Quantity</label>
                            <input type="number" name="quantity" class="input" placeholder="Enter quantity" required 
                                style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease;" />
                        </div>
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Close Time (optional)</label>
                        <input type="datetime-local" name="close_time" id="close_time" class="input" 
                        style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 20px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Upload Image (optional)</label>
                        <input type="file" name="image" id="item_image" class="input" accept="image/*" 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease;" />
                    </div>
                    
                    <button type="submit" class="admin-btn" 
                        style="width: 100%; padding: 12px; background: #48dbfb; color: white; border: none; border-radius: 8px; font-size: 14px; cursor: pointer; transition: background 0.3s;">
                        <i class="fas fa-save"></i> Submit Buy Request
                    </button>
                </form>
            </div>

        <?php elseif ($_GET['action'] == 'items_for_sell'): ?>
            <?php
            // Initialize items array
            $items = [];
            
            // Pagination setup
            $items_per_page = 12;
            $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
            $offset = ($page - 1) * $items_per_page;
            
            try {
                // Get total count of items
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM items WHERE posted_by = :user_id");
                $stmt->execute([':user_id' => $_SESSION['user_id']]);
                $total_items = $stmt->fetchColumn();
                
                // Calculate total pages
                $total_pages = ceil($total_items / $items_per_page);
                
                // Fetch items with pagination
                $stmt = $pdo->prepare("SELECT * FROM items WHERE posted_by = :user_id ORDER BY created_at DESC LIMIT :limit OFFSET :offset");
                $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
                $stmt->bindValue(':limit', $items_per_page, PDO::PARAM_INT);
                $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
                $stmt->execute();
                $items = $stmt->fetchAll();
            } catch (PDOException $e) {
                error_log("Error fetching items: " . $e->getMessage());
                $error = "Error fetching items. Please try again later.";
            }
            ?>
            
            <div class="section-title">
                <h2>Items for Sale</h2>
                <a href="?action=post_sell" class="admin-btn">Post New Item</a>
            </div>

            <?php if (empty($items)): ?>
                <div class="no-items">
                    <p>No items found. <a href="?action=post_sell">Post your first item</a></p>
                </div>
            <?php else: ?>
                <div class="items-grid">
                    <?php foreach ($items as $item): ?>
                        <div class="item-card <?php echo $item['status'] === 'closed' ? 'closed' : ''; ?>" data-id="<?php echo $item['id']; ?>">
                            <div class="card-image">
                                <img src="<?php echo htmlspecialchars($item['image_path']); ?>" alt="<?php echo htmlspecialchars($item['item_name']); ?>">
                                <?php if ($item['status'] === 'closed'): ?>
                                    <div class="card-status">Closed</div>
                                <?php endif; ?>
                            </div>
                            <div class="card-content">
                                <div class="card-info">
                                    <div class="info-row">
                                        <span class="info-label">Name:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($item['item_name']); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Description:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($item['description']); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Price:</span>
                                        <span class="info-value">$<?php echo number_format($item['price'], 2); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Quantity:</span>
                                        <span class="info-value"><?php echo $item['quantity']; ?> available</span>
                                    </div>
                                    <?php if ($item['close_time']): ?>
                                        <div class="info-row">
                                            <span class="info-label">Closes:</span>
                                            <span class="info-value countdown" data-close-time="<?php echo $item['close_time']; ?>">
                                                <?php echo date('M d, Y H:i', strtotime($item['close_time'])); ?>
                                            </span>
                                        </div>
                                    <?php endif; ?>
                                </div>
                                <div class="card-actions">
                                    <button class="admin-btn primary" onclick="showEditForm(<?php echo $item['id']; ?>, 'sell')">Edit</button>
                                    <button class="admin-btn danger" onclick="deleteItem(<?php echo $item['id']; ?>, 'sell')">Delete</button>
                                    <?php if ($item['status'] === 'active'): ?>
                                        <button class="admin-btn warning" onclick="closeItem(<?php echo $item['id']; ?>, 'sell')">Close</button>
                                    <?php else: ?>
                                        <button class="admin-btn success" onclick="reopenItem(<?php echo $item['id']; ?>, 'sell')">Reopen</button>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>

                <?php if ($total_pages > 1): ?>
                    <div class="pagination">
                        <?php if ($page > 1): ?>
                            <a href="?action=items_for_sell&page=<?php echo $page - 1; ?>" class="admin-btn small">Previous</a>
                        <?php endif; ?>
                        
                        <?php if ($page < $total_pages): ?>
                            <a href="?action=items_for_sell&page=<?php echo $page + 1; ?>" class="admin-btn small">Next</a>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'buy_requests'): ?>
            <?php
            // Initialize buy_requests array
            $buy_requests = [];
            
            // Pagination setup
            $items_per_page = 12;
            $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
            $offset = ($page - 1) * $items_per_page;
            
            try {
                // Get total count of buy requests
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM buy_requests WHERE user_id = :user_id");
                $stmt->execute([':user_id' => $_SESSION['user_id']]);
                $total_requests = $stmt->fetchColumn();
                
                // Calculate total pages
                $total_pages = ceil($total_requests / $items_per_page);
                
                // Fetch buy requests with pagination
                $stmt = $pdo->prepare("SELECT * FROM buy_requests WHERE user_id = :user_id ORDER BY created_at DESC LIMIT :limit OFFSET :offset");
                $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
                $stmt->bindValue(':limit', $items_per_page, PDO::PARAM_INT);
                $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
                $stmt->execute();
                $buy_requests = $stmt->fetchAll();
            } catch (PDOException $e) {
                error_log("Error fetching buy requests: " . $e->getMessage());
                $error = "Error fetching buy requests. Please try again later.";
            }
            ?>
            
            <div class="section-title">
                <h2>Active Buy Requests</h2>
                <a href="?action=post_buy" class="admin-btn">Post New Request</a>
            </div>

            <?php if (empty($buy_requests)): ?>
                <div class="no-items">
                    <p>No buy requests found. <a href="?action=post_buy">Create your first request</a></p>
                </div>
            <?php else: ?>
                <div class="items-grid">
                    <?php foreach ($buy_requests as $request): ?>
                        <div class="item-card <?php echo $request['status'] === 'closed' ? 'closed' : ''; ?>" data-id="<?php echo $request['id']; ?>">
                            <div class="card-image">
                                <img src="<?php echo htmlspecialchars($request['image_path']); ?>" alt="<?php echo htmlspecialchars($request['item_name']); ?>">
                                <?php if ($request['status'] === 'closed'): ?>
                                    <div class="card-status">Closed</div>
                                <?php endif; ?>
                            </div>
                            <div class="card-content">
                                <div class="card-info">
                                    <div class="info-row">
                                        <span class="info-label">Name:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($request['item_name']); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Description:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($request['description']); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Max Price:</span>
                                        <span class="info-value">$<?php echo number_format($request['max_price'], 2); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Quantity:</span>
                                        <span class="info-value"><?php echo $request['quantity']; ?> needed</span>
                                    </div>
                                    <?php if ($request['close_time']): ?>
                                        <div class="info-row">
                                            <span class="info-label">Closes:</span>
                                            <span class="info-value countdown" data-close-time="<?php echo $request['close_time']; ?>">
                                                <?php echo date('M d, Y H:i', strtotime($request['close_time'])); ?>
                                            </span>
                                        </div>
                                    <?php endif; ?>
                                </div>
                                <div class="card-actions">
                                    <button class="admin-btn primary" onclick="showEditForm(<?php echo $request['id']; ?>, 'buy')">Edit</button>
                                    <button class="admin-btn danger" onclick="deleteItem(<?php echo $request['id']; ?>, 'buy')">Delete</button>
                                    <?php if ($request['status'] === 'active'): ?>
                                        <button class="admin-btn warning" onclick="closeItem(<?php echo $request['id']; ?>, 'buy')">Close</button>
                                    <?php else: ?>
                                        <button class="admin-btn success" onclick="reopenItem(<?php echo $request['id']; ?>, 'buy')">Reopen</button>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'transactions'): ?>
            <!-- Transactions -->
            <div class="table-card">
                <h2><i class="fas fa-receipt"></i> Transactions</h2>
                <?php if (empty($transactions)): ?>
                    <p>No transactions found.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Item Name</th>
                                    <th>Type</th>
                                    <th>Buyer</th>
                                    <th>Seller</th>
                                    <th>Final Price ($)</th>
                                    <th>Quantity</th>
                                    <th>Total Amount ($)</th>
                                    <th>Date</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($transactions as $t): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($t['id'], ENT_QUOTES, 'UTF-8'); ?></td>
                                        <td><?php echo htmlspecialchars($t['item_name_sell'] ?? $t['item_name_buy'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
                                        <td><?php echo $t['item_id'] ? 'Sell' : 'Buy'; ?></td>
                                        <td><?php echo htmlspecialchars($t['buyer'], ENT_QUOTES, 'UTF-8'); ?></td>
                                        <td><?php echo htmlspecialchars($t['seller'], ENT_QUOTES, 'UTF-8'); ?></td>
                                        <td><?php echo htmlspecialchars($t['final_price'], ENT_QUOTES, 'UTF-8'); ?></td>
                                        <td><?php echo htmlspecialchars($t['quantity'], ENT_QUOTES, 'UTF-8'); ?></td>
                                        <td><?php echo htmlspecialchars($t['final_price'] * $t['quantity'], ENT_QUOTES, 'UTF-8'); ?></td>
                                        <td><?php echo htmlspecialchars($t['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <!-- Pagination -->
                    <div class="pagination">
                        <?php
                        $total_pages = ceil($total_transactions / $items_per_page);
                        if ($total_pages > 1):
                        ?>
                            <div class="pagination-links">
                                <?php if ($page > 1): ?>
                                    <a href="?action=transactions&page=<?php echo $page - 1; ?>" class="admin-btn small">Previous</a>
                                <?php endif; ?>
                                <span>Page <?php echo $page; ?> of <?php echo $total_pages; ?></span>
                                <?php if ($page < $total_pages): ?>
                                    <a href="?action=transactions&page=<?php echo $page + 1; ?>" class="admin-btn small">Next</a>
                                <?php endif; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- Footer -->
<footer id="footer">
    <div class="inner-width">
        <div class="footer-content">
            <div class="footer-section">
                <h3>About Us</h3>
                <p>We are a platform dedicated to facilitating online bidding and transactions securely and efficiently.</p>
            </div>
            <div class="footer-section">
                <h3>Quick Links</h3>
                <ul>
                    <li><a href="../index.php">Home</a></li>
                    <li><a href="../index.php#about">About</a></li>
                    <li><a href="../index.php#contact">Contact</a></li>
                    <li><a href="admin_dashboard.php">Dashboard</a></li>
                </ul>
            </div>
            <div class="footer-section">
                <h3>Contact Us</h3>
                <p>Email: support@example.com</p>
                <p>Phone: (123) 456-7890</p>
            </div>
        </div>
        <div class="footer-bottom">
            <p>&copy; <?php echo date('Y'); ?> Online Bidding System. All rights reserved.</p>
        </div>
    </div>
</footer>

<script>
    // Navbar toggle
    $(document).ready(function () {
        $('.menu-toggler').on('click', function () {
            $(this).toggleClass('active');
            $('.navbar-menu').toggleClass('active');
        });

        $('.navbar-menu a').on('click', function () {
            $('.menu-toggler').removeClass('active');
            $('.navbar-menu').removeClass('active');
        });
    });

    // Tag input functionality
    function addTag(formType) {
        const input = document.getElementById(`tag-input-${formType}`);
        const container = document.getElementById(`tag-container-${formType}`);
        const errorText = document.getElementById(`tag-error-${formType}`);
        let tagText = input.value.trim();

        if (tagText === '') return;

        // Prevent duplicate tags (case-insensitive)
        const existingTags = Array.from(container.getElementsByClassName('tag')).map(tag => tag.textContent.replace('×', '').trim().toLowerCase());
        if (existingTags.includes(tagText.toLowerCase())) {
            errorText.textContent = 'This tag already exists.';
            errorText.style.display = 'block';
            input.value = '';
            return;
        }

        // Validate tag format (only letters, numbers, spaces, and hyphens)
        const tagRegex = /^[a-zA-Z0-9\s-]+$/;
        if (!tagRegex.test(tagText)) {
            errorText.textContent = 'Tags can only contain letters, numbers, spaces, and hyphens.';
            errorText.style.display = 'block';
            return;
        }

        errorText.style.display = 'none';

        const tag = document.createElement('span');
        tag.className = 'tag';
        tag.innerHTML = `${tagText}<span class="remove-tag" onclick="removeTag(this, '${formType}')">×</span>`;
        container.appendChild(tag);
        input.value = '';
        updateHiddenTags(`item-types-${formType}`);
    }

    function removeTag(element, formType) {
        element.parentElement.remove();
        updateHiddenTags(`item-types-${formType}`);
    }

    function updateHiddenTags(hiddenInputId) {
        const container = document.getElementById(`tag-container-${hiddenInputId.split('-').pop()}`);
        const hiddenInput = document.getElementById(hiddenInputId);
        const errorText = document.getElementById(`tag-error-${hiddenInputId.split('-').pop()}`);
        const tags = Array.from(container.getElementsByClassName('tag'))
            .map(tag => tag.textContent.replace('×', '').trim())
            .filter(tag => tag !== '');
        
        hiddenInput.value = tags.join(', ');

        // Validate that at least one tag exists
        if (tags.length === 0) {
            errorText.textContent = 'At least one tag is required.';
            errorText.style.display = 'block';
            return false;
        } else {
            errorText.style.display = 'none';
            return true;
        }
    }

    // Add tag on Enter key press or button click
    document.addEventListener('DOMContentLoaded', function() {
        // For sell form
        const sellInput = document.getElementById('tag-input-sell');
        const sellButton = document.getElementById('add-tag-sell');
        if (sellInput && sellButton) {
            sellInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    addTag('sell');
                }
            });
            sellButton.addEventListener('click', function() {
                addTag('sell');
            });
        }

        // For buy form
        const buyInput = document.getElementById('tag-input-buy');
        const buyButton = document.getElementById('add-tag-buy');
        if (buyInput && buyButton) {
            buyInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    addTag('buy');
                }
            });
            buyButton.addEventListener('click', function() {
                addTag('buy');
            });
        }

        // For edit form
        const editInput = document.getElementById('tag-input-edit');
        const editButton = document.getElementById('add-tag-edit');
        if (editInput && editButton) {
            editInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    addTag('edit');
                }
            });
            editButton.addEventListener('click', function() {
                addTag('edit');
            });
        }
    });

    // Ensure form submission validates tags
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function (e) {
            const hiddenInput = form.querySelector('input[name="item_types"]');
            if (hiddenInput) {
                const formType = hiddenInput.id.split('-').pop();
                if (!updateHiddenTags(`item-types-${formType}`)) {
                    e.preventDefault();
                }
            }
        });
    });

    // Countdown timer function
    function updateCountdown(itemId, closeTime) {
        const timerElement = document.querySelector(`.countdown-timer[data-item-id="${itemId}"]`);
        if (!timerElement) return;

        const now = new Date().getTime();
        const closeDate = new Date(closeTime).getTime();
        const distance = closeDate - now;

        if (distance < 0) {
            timerElement.innerHTML = '<i class="fas fa-clock"></i> Closed';
            timerElement.classList.add('closed');
            return;
        }

        const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((distance % (1000 * 60)) / 1000);

        timerElement.innerHTML = `<i class="fas fa-clock"></i> ${hours}h ${minutes}m ${seconds}s`;
        
        if (hours < 1) {
            timerElement.classList.add('closing-soon');
        }
    }

    // Edit item function
    function editItem(itemId, itemType) {
        console.log('Edit button clicked for item:', itemId, 'type:', itemType);
        
        // Create overlay
        const overlay = document.createElement('div');
        overlay.className = 'overlay active';
        document.body.appendChild(overlay);

        // Find and show edit form
        const editForm = document.querySelector(`.edit-form-container[data-item-id="${itemId}"][data-item-type="${itemType}"]`);
        if (!editForm) {
            console.error('Edit form not found for item:', itemId, 'type:', itemType);
            return;
        }

        editForm.style.display = 'block';
        editForm.classList.add('active');

        // Close form when clicking overlay
        overlay.addEventListener('click', () => {
            cancelEdit(itemId, itemType);
        });
    }

    // Save edit function
    function saveEdit(itemId, itemType) {
        const form = document.querySelector(`.edit-form-container[data-item-id="${itemId}"][data-item-type="${itemType}"] .edit-form`);
        if (!form) {
            console.error('Form not found for item:', itemId, 'type:', itemType);
            return;
        }

        const formData = new FormData(form);
        formData.append('action', 'update');
        formData.append('item_id', itemId);
        formData.append('item_type', itemType);
        
        fetch(window.location.href, {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (response.ok) {
                window.location.reload();
            } else {
                throw new Error('Network response was not ok');
            }
        })
        .catch(error => {
            showAlert('Error saving changes: ' + error.message, 'error');
        });
    }

    // Cancel edit function
    function cancelEdit(itemId, itemType) {
        const editForm = document.querySelector(`.edit-form-container[data-item-id="${itemId}"][data-item-type="${itemType}"]`);
        const overlay = document.querySelector('.overlay');
        
        if (editForm) {
            editForm.style.display = 'none';
            editForm.classList.remove('active');
        }
        if (overlay) {
            overlay.remove();
        }
    }

    // Delete item function
    function deleteItem(itemId, itemType) {
        if (confirm('Are you sure you want to delete this item?')) {
            $.ajax({
                url: 'admin_dashboard.php',
                type: 'POST',
                data: {
                    action: 'delete',
                    item_id: itemId,
                    item_type: itemType
                },
                success: function(response) {
                    showAlert('Item deleted successfully', 'success');
                    setTimeout(() => location.reload(), 1500);
                },
                error: function() {
                    showAlert('Error deleting item', 'error');
                }
            });
        }
    }

    // Close item function
    function closeItem(itemId) {
        if (confirm('Are you sure you want to close this item?')) {
            $.ajax({
                url: 'admin_dashboard.php',
                type: 'POST',
                data: {
                    action: 'close',
                    item_id: itemId
                },
                success: function(response) {
                    showAlert('Item closed successfully', 'success');
                    setTimeout(() => location.reload(), 1500);
                },
                error: function() {
                    showAlert('Error closing item', 'error');
                }
            });
        }
    }

    // Initialize countdown timers
    document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('.countdown-timer').forEach(timer => {
            const itemId = timer.dataset.itemId;
            const closeTime = timer.dataset.closeTime;
            if (itemId && closeTime) {
                updateCountdown(itemId, closeTime);
                setInterval(() => updateCountdown(itemId, closeTime), 1000);
            }
        });
    });

    // Show success/error messages
    function showAlert(message, type) {
        const alertDiv = $('<div>')
            .addClass(`alert alert-${type}`)
            .text(message)
            .appendTo('body');
        
        setTimeout(() => alertDiv.remove(), 3000);
    }

    // Reopen item function
    function reopenItem(itemId) {
        if (confirm('Are you sure you want to reopen this item?')) {
            $.ajax({
                url: 'admin_dashboard.php',
                type: 'POST',
                data: {
                    action: 'reopen',
                    item_id: itemId
                },
                success: function(response) {
                    showAlert('Item reopened successfully', 'success');
                    setTimeout(() => location.reload(), 1500);
                },
                error: function() {
                    showAlert('Error reopening item', 'error');
                }
            });
        }
    }

    // JavaScript functions for item actions
    function deleteItem(itemId, itemType) {
        if (confirm('Are you sure you want to delete this item?')) {
            $.ajax({
                url: 'admin_dashboard.php',
                type: 'POST',
                data: {
                    action: 'delete',
                    item_id: itemId,
                    item_type: itemType
                },
                success: function(response) {
                    showAlert('Item deleted successfully', 'success');
                    setTimeout(() => location.reload(), 1500);
                },
                error: function() {
                    showAlert('Error deleting item', 'error');
                }
            });
        }
    }

    function closeItem(itemId) {
        if (confirm('Are you sure you want to close this item?')) {
            $.ajax({
                url: 'admin_dashboard.php',
                type: 'POST',
                data: {
                    action: 'close',
                    item_id: itemId
                },
                success: function(response) {
                    showAlert('Item closed successfully', 'success');
                    setTimeout(() => location.reload(), 1500);
                },
                error: function() {
                    showAlert('Error closing item', 'error');
                }
            });
        }
    }

    function reopenItem(itemId) {
        if (confirm('Are you sure you want to reopen this item?')) {
            $.ajax({
                url: 'admin_dashboard.php',
                type: 'POST',
                data: {
                    action: 'reopen',
                    item_id: itemId
                },
                success: function(response) {
                    showAlert('Item reopened successfully', 'success');
                    setTimeout(() => location.reload(), 1500);
                },
                error: function() {
                    showAlert('Error reopening item', 'error');
                }
            });
        }
    }

    function showEditForm(itemId, itemType) {
        // Create overlay
        const overlay = document.createElement('div');
        overlay.className = 'overlay';
        document.body.appendChild(overlay);
        
        // Show form
        const form = $(`#edit-form-${itemId}`);
        if (form.length) {
            form.show();
            form.addClass('active');
            overlay.classList.add('active');
        } else {
            // If form doesn't exist, create it
            const formHtml = `
                <div class="edit-form-container" id="edit-form-${itemId}">
                    <form class="edit-form" onsubmit="saveEdit(${itemId}, '${itemType}'); return false;">
                        <h3>Edit ${itemType === 'sell' ? 'Item' : 'Buy Request'}</h3>
                        <div class="form-group">
                            <label>Name:</label>
                            <input type="text" name="item_name" class="input" required placeholder="Enter item name">
                        </div>
                        <div class="form-group">
                            <label>Description:</label>
                            <textarea name="description" class="input" required placeholder="Enter item description"></textarea>
                        </div>
                        <div class="form-group">
                            <label>${itemType === 'sell' ? 'Price ($):' : 'Max Price ($):'}</label>
                            <input type="number" name="price" class="input" step="0.01" required placeholder="Enter price">
                        </div>
                        <div class="form-group">
                            <label>Quantity:</label>
                            <input type="number" name="quantity" class="input" required placeholder="Enter quantity">
                        </div>
                        <div class="form-group">
                            <label>Close Time (optional):</label>
                            <input type="datetime-local" name="close_time" class="input" placeholder="Select close time">
                        </div>
                        <div class="form-actions">
                            <button type="submit" class="admin-btn success">Save Changes</button>
                            <button type="button" class="admin-btn danger" onclick="hideEditForm(${itemId})">Cancel</button>
                        </div>
                    </form>
                </div>
            `;
            $('body').append(formHtml);
            const newForm = $(`#edit-form-${itemId}`);
            newForm.show();
            newForm.addClass('active');
            overlay.classList.add('active');
            
            // Load current values
            $.ajax({
                url: 'admin_dashboard.php',
                type: 'GET',
                data: {
                    action: 'get_item',
                    item_id: itemId,
                    item_type: itemType
                },
                success: function(response) {
                    const data = JSON.parse(response);
                    if (data) {
                        newForm.find('[name="item_name"]').val(data.item_name);
                        newForm.find('[name="description"]').val(data.description);
                        newForm.find('[name="price"]').val(data.price || data.max_price);
                        newForm.find('[name="quantity"]').val(data.quantity);
                        if (data.close_time) {
                            newForm.find('[name="close_time"]').val(data.close_time.replace(' ', 'T'));
                        }
                    }
                }
            });
        }
    }

    function hideEditForm(itemId) {
        const form = $(`#edit-form-${itemId}`);
        const overlay = $('.overlay');
        
        if (form.length) {
            form.hide();
            form.removeClass('active');
        }
        if (overlay.length) {
            overlay.remove();
        }
    }

    function saveEdit(itemId, itemType) {
        const form = $(`#edit-form-${itemId}`);
        const formData = new FormData(form[0]);
        formData.append('action', 'update');
        formData.append('item_id', itemId);
        formData.append('item_type', itemType);

        $.ajax({
            url: 'admin_dashboard.php',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                showAlert('Item updated successfully', 'success');
                setTimeout(() => location.reload(), 1500);
            },
            error: function() {
                showAlert('Error updating item', 'error');
            }
        });
    }

    // Add overlay click handler to close form
    $(document).on('click', '.overlay', function() {
        $('.edit-form-container').hide().removeClass('active');
        $(this).remove();
    });

    // Prevent form click from closing the overlay
    $(document).on('click', '.edit-form-container', function(e) {
        e.stopPropagation();
    });

    // Initialize countdown timers
    function initializeCountdowns() {
        $('.countdown').each(function() {
            const endTime = new Date($(this).data('end-time')).getTime();
            const timer = $(this);
            
            const updateTimer = () => {
                const now = new Date().getTime();
                const distance = endTime - now;
                
                if (distance < 0) {
                    timer.html('Closed');
                    return;
                }
                
                const days = Math.floor(distance / (1000 * 60 * 60 * 24));
                const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                const seconds = Math.floor((distance % (1000 * 60)) / 1000);
                
                timer.html(`${days}d ${hours}h ${minutes}m ${seconds}s`);
            };
            
            updateTimer();
            setInterval(updateTimer, 1000);
        });
    }

    // Initialize when document is ready
    $(document).ready(function() {
        initializeCountdowns();
    });
</script>
</body>
</html>