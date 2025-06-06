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
                $item_types = isset($_POST['item_types']) ? sanitizeInput(trim($_POST['item_types'])) : '';

                // Validate item types
                if (empty($item_types)) {
                    $error = "Please add at least one item type.";
                }

                // Handle image upload
                $image_path = null;
                if (isset($_FILES['image']) && $_FILES['image']['error'] == 0) {
                    $allowed = ['jpg', 'jpeg', 'png', 'gif'];
                    $filename = $_FILES['image']['name'];
                    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

                    if (!in_array($ext, $allowed)) {
                        $error = "Invalid file format. Allowed formats: " . implode(', ', $allowed);
                    } else {
                        $upload_dir = '../Uploads/';
                        if (!file_exists($upload_dir)) {
                            mkdir($upload_dir, 0777, true);
                        }
                        $image_path = $upload_dir . uniqid() . '_' . $filename;
                        move_uploaded_file($_FILES['image']['tmp_name'], $image_path);
                    }
                }

                if (!isset($error)) {
                    $stmt = $pdo->prepare("INSERT INTO items (supplier_name, item_name, item_type, description, price, quantity, status, image, close_time, created_at, posted_by) VALUES (:supplier_name, :item_name, :item_type, :description, :price, :quantity, 'available', :image, :close_time, NOW(), :posted_by)");
                    $stmt->execute([
                        ':supplier_name' => $supplier_name,
                        ':item_name' => $item_name,
                        ':item_type' => $item_types,
                        ':description' => $description,
                        ':price' => $price,
                        ':quantity' => $quantity,
                        ':image' => $image_path ?? null,
                        ':close_time' => $close_time,
                        ':posted_by' => $_SESSION['user_id']
                    ]);
                    $success = "Item posted successfully!";
                    header("Location: admin_dashboard.php?action=items_for_sell");
                    exit();
                }
            } catch (PDOException $e) {
                $error = "Error posting item: " . $e->getMessage();
            }
        }
    }
}

// Handle Post Buy Item
if (isset($_GET['action']) && $_GET['action'] == 'post_buy') {
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
                $item_types = isset($_POST['item_types']) ? sanitizeInput(trim($_POST['item_types'])) : '';

                // Validate item types
                if (empty($item_types)) {
                    $error = "Please add at least one item type.";
                }

                // Handle image upload
                $image_path = null;
                if (isset($_FILES['image']) && $_FILES['image']['error'] == 0) {
                    $allowed = ['jpg', 'jpeg', 'png', 'gif'];
                    $filename = $_FILES['image']['name'];
                    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

                    if (!in_array($ext, $allowed)) {
                        $error = "Invalid file format. Allowed formats: " . implode(', ', $allowed);
                    } else {
                        $upload_dir = '../Uploads/';
                        if (!file_exists($upload_dir)) {
                            mkdir($upload_dir, 0777, true);
                        }
                        $image_path = $upload_dir . uniqid() . '_' . $filename;
                        move_uploaded_file($_FILES['image']['tmp_name'], $image_path);
                    }
                }

                if (!isset($error)) {
                    $stmt = $pdo->prepare("INSERT INTO buy_requests (item_name, item_type, description, max_price, quantity, status, image, close_time, created_at, user_id) VALUES (:item_name, :item_type, :description, :max_price, :quantity, 'open', :image, :close_time, NOW(), :user_id)");
                    $stmt->execute([
                        ':item_name' => $item_name,
                        ':item_type' => $item_types,
                        ':description' => $description,
                        ':max_price' => $max_price,
                        ':quantity' => $quantity,
                        ':image' => $image_path ?? null,
                        ':close_time' => $close_time,
                        ':user_id' => $_SESSION['user_id']
                    ]);
                    $success = "Buy request posted successfully!";
                    header("Location: admin_dashboard.php?action=buy_requests");
                    exit();
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
                $item_types = isset($_POST['item_types']) ? sanitizeInput($_POST['item_types']) : '';

                // Validate inputs
                if (empty($supplier_name) || empty($item_name) || empty($description) || $price <= 0 || $quantity < 0) {
                    $error = "All fields are required and must be valid.";
                } else {
                    // Handle image upload if new image is provided
                    $image_path = $_POST['existing_image'] ?? null;
                    if (isset($_FILES['image']) && $_FILES['image']['error'] == UPLOAD_ERR_OK) {
                        $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
                        $max_size = 5 * 1024 * 1024; // 5MB
                        
                        if (!in_array($_FILES['image']['type'], $allowed_types)) {
                            $error = "Invalid file type. Only JPG, PNG and GIF are allowed.";
                        } elseif ($_FILES['image']['size'] > $max_size) {
                            $error = "File is too large. Maximum size is 5MB.";
                        } else {
                            $upload_dir = '../uploads/';
                            if (!is_dir($upload_dir)) {
                                mkdir($upload_dir, 0777, true);
                            }
                            
                            $file_extension = pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION);
                            $new_filename = uniqid('item_') . '.' . $file_extension;
                            $upload_path = $upload_dir . $new_filename;
                            
                            if (move_uploaded_file($_FILES['image']['tmp_name'], $upload_path)) {
                                $image_path = 'uploads/' . $new_filename;
                            } else {
                                $error = "Failed to upload image.";
                            }
                        }
                    }

                    if (!isset($error)) {
                        // Update the database
                        $stmt = $pdo->prepare("
                            UPDATE items 
                            SET supplier_name = :supplier_name,
                                item_name = :item_name,
                                description = :description,
                                price = :price,
                                quantity = :quantity,
                                item_type = :item_types" . 
                                ($image_path ? ", image = :image" : "") . "
                            WHERE id = :item_id AND posted_by = :user_id
                        ");

                        $params = [
                            ':supplier_name' => $supplier_name,
                            ':item_name' => $item_name,
                            ':description' => $description,
                            ':price' => $price,
                            ':quantity' => $quantity,
                            ':item_types' => $item_types,
                            ':item_id' => $item_id,
                            ':user_id' => $_SESSION['user_id']
                        ];

                        if ($image_path) {
                            $params[':image'] = $image_path;
                        }

                        $stmt->execute($params);

                        if ($stmt->rowCount() > 0) {
                            $_SESSION['success_message'] = "Item updated successfully!";
                            header("Location: admin_dashboard.php?action=items_for_sell");
                            exit();
                        } else {
                            $error = "No changes were made or you don't have permission to edit this item.";
                        }
                    }
                }
            } catch (PDOException $e) {
                $error = "Error updating item: " . $e->getMessage();
            }
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
                        $upload_dir = dirname(__DIR__) . '/Uploads/';
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
                            $image_path = 'Uploads/' . $file_name;
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

// Handle Close/Open Item
if (isset($_GET['action']) && ($_GET['action'] == 'close_item' || $_GET['action'] == 'open_item') && isset($_GET['item_id'])) {
    $item_id = intval($_GET['item_id']);
    $new_status = $_GET['action'] == 'close_item' ? 'closed' : 'open';
    try {
        $stmt = $pdo->prepare("SELECT * FROM items WHERE id = :item_id AND posted_by = :posted_by");
        $stmt->execute([
            ':item_id' => $item_id,
            ':posted_by' => $_SESSION['user_id']
        ]);
        $item = $stmt->fetch();

        if (!$item) {
            $error = "Item not found or you don't have permission to modify it.";
        } else {
            $stmt = $pdo->prepare("UPDATE items SET status = :status WHERE id = :item_id AND posted_by = :posted_by");
            $stmt->execute([
                ':status' => $new_status,
                ':item_id' => $item_id,
                ':posted_by' => $_SESSION['user_id']
            ]);
            if ($stmt->rowCount() > 0) {
                $success = "Item " . ($new_status == 'closed' ? 'closed' : 'reopened') . " successfully!";
            } else {
                $error = "Failed to update item status.";
            }
        }
        header("Location: admin_dashboard.php?action=items_for_sell");
        exit();
    } catch (PDOException $e) {
        $error = "Error modifying item: " . $e->getMessage();
    }
}

// Handle Close/Open Buy Request
if (isset($_GET['action']) && ($_GET['action'] == 'close_buy_request' || $_GET['action'] == 'open_buy_request') && isset($_GET['request_id'])) {
    $request_id = intval($_GET['request_id']);
    $new_status = $_GET['action'] == 'close_buy_request' ? 'closed' : 'open';
    try {
        $stmt = $pdo->prepare("SELECT * FROM buy_requests WHERE id = :request_id AND user_id = :user_id");
        $stmt->execute([
            ':request_id' => $request_id,
            ':user_id' => $_SESSION['user_id']
        ]);
        $request = $stmt->fetch();

        if (!$request) {
            $error = "Buy request not found or you don't have permission to modify it.";
        } else {
            $stmt = $pdo->prepare("UPDATE buy_requests SET status = :status WHERE id = :request_id AND user_id = :user_id");
            $stmt->execute([
                ':status' => $new_status,
                ':request_id' => $request_id,
                ':user_id' => $_SESSION['user_id']
            ]);
            if ($stmt->rowCount() > 0) {
                $success = "Buy request " . ($new_status == 'closed' ? 'closed' : 'reopened') . " successfully!";
            } else {
                $error = "Failed to update buy request status.";
            }
        }
        header("Location: admin_dashboard.php?action=buy_requests");
        exit();
    } catch (PDOException $e) {
        $error = "Error modifying buy request: " . $e->getMessage();
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
        us.username AS seller,
        o.status AS offer_status
    FROM transactions t 
    LEFT JOIN items i ON t.item_id = i.id 
    LEFT JOIN buy_requests br ON t.request_id = br.id 
    JOIN users ub ON t.buyer_or_seller_id = ub.id 
    LEFT JOIN users us ON (i.posted_by = us.id OR br.user_id = us.id)
    LEFT JOIN offers o ON t.offer_id = o.id
    WHERE (i.posted_by = :user_id1 OR br.user_id = :user_id2)
    AND o.status IN ('accepted', 'completed')
    ORDER BY t.created_at DESC
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

// Fetch item or buy request data for editing
if (isset($_GET['action']) && isset($_GET['item_id'])) {
    if ($_GET['action'] == 'edit_item') {
        try {
            $stmt = $pdo->prepare("SELECT * FROM items WHERE id = :item_id AND posted_by = :user_id");
            $stmt->execute([
                ':item_id' => intval($_GET['item_id']),
                ':user_id' => $_SESSION['user_id']
            ]);
            $item_to_edit = $stmt->fetch();
        } catch (PDOException $e) {
            $error = "Error fetching item: " . $e->getMessage();
        }
    }
}

if (isset($_GET['action']) && isset($_GET['request_id'])) {
    if ($_GET['action'] == 'edit_buy_request') {
        try {
            $stmt = $pdo->prepare("SELECT * FROM buy_requests WHERE id = :request_id AND user_id = :user_id");
            $stmt->execute([
                ':request_id' => intval($_GET['request_id']),
                ':user_id' => $_SESSION['user_id']
            ]);
            $request_to_edit = $stmt->fetch();
        } catch (PDOException $e) {
            $error = "Error fetching buy request: " . $e->getMessage();
        }
    }
}

// Handle edit item form submission
if (isset($_POST['edit_item_submit'])) {
    try {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            throw new Exception("Invalid CSRF token");
        }

        $item_id = intval($_POST['item_id']);
        $supplier_name = sanitizeInput($_POST['supplier_name']);
        $item_name = sanitizeInput($_POST['item_name']);
        $description = sanitizeInput($_POST['description']);
        $price = floatval($_POST['price']);
        $quantity = intval($_POST['quantity']);
        $item_types = sanitizeInput($_POST['item_types']);

        // Validate inputs
        if (empty($supplier_name) || empty($item_name) || empty($description) || $price <= 0 || $quantity < 0) {
            throw new Exception("All fields are required and must be valid");
        }

        // Handle image upload
        $image_path = $_POST['existing_image'];
        if (isset($_FILES['image']) && $_FILES['image']['error'] == UPLOAD_ERR_OK) {
            $upload_dir = '../uploads/';
            if (!is_dir($upload_dir)) {
                mkdir($upload_dir, 0777, true);
            }

            $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
            if (!in_array($_FILES['image']['type'], $allowed_types)) {
                throw new Exception("Invalid file type. Only JPG, PNG and GIF are allowed.");
            }

            $file_extension = pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION);
            $new_filename = uniqid('item_') . '.' . $file_extension;
            $full_path = $upload_dir . $new_filename;

            if (move_uploaded_file($_FILES['image']['tmp_name'], $full_path)) {
                $image_path = 'uploads/' . $new_filename;
            } else {
                throw new Exception("Failed to upload image");
            }
        }

        // Update database
        $stmt = $pdo->prepare("
            UPDATE items 
            SET supplier_name = :supplier_name,
                item_name = :item_name,
                description = :description,
                price = :price,
                quantity = :quantity,
                item_type = :item_types,
                image = :image,
                updated_at = NOW()
            WHERE id = :item_id AND posted_by = :user_id
        ");

        $result = $stmt->execute([
            ':supplier_name' => $supplier_name,
            ':item_name' => $item_name,
            ':description' => $description,
            ':price' => $price,
            ':quantity' => $quantity,
            ':item_types' => $item_types,
            ':image' => $image_path,
            ':item_id' => $item_id,
            ':user_id' => $_SESSION['user_id']
        ]);

        if (!$result) {
            throw new Exception("Failed to update item");
        }

        if ($stmt->rowCount() === 0) {
            throw new Exception("No changes were made or you don't have permission to edit this item");
        }

        $_SESSION['success_message'] = "Item updated successfully!";
        
        // If it's an AJAX request, send JSON response
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            header('Content-Type: application/json');
            echo json_encode(['success' => true, 'message' => 'Item updated successfully']);
            exit;
        }

        // Regular form submission
        header("Location: admin_dashboard.php?action=items_for_sell");
        exit();

    } catch (Exception $e) {
        error_log("Error updating item: " . $e->getMessage());
        $_SESSION['error_message'] = $e->getMessage();

        // If it's an AJAX request, send JSON response
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            header('Content-Type: application/json');
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
            exit;
        }

        // Regular form submission
        header("Location: admin_dashboard.php?action=items_for_sell");
        exit();
    }
}

// Handle edit buy request form submission
if (isset($_POST['edit_request_submit'])) {
    try {
        $request_id = intval($_POST['request_id']);
        $item_name = sanitizeInput($_POST['item_name']);
        $description = sanitizeInput($_POST['description']);
        $max_price = floatval($_POST['max_price']);
        $quantity = intval($_POST['quantity']);
        $item_types = sanitizeInput($_POST['item_types']);

        // Handle image upload
        $image_path = $_POST['existing_image'];
        if (isset($_FILES['image']) && $_FILES['image']['error'] == UPLOAD_ERR_OK) {
            $upload_dir = '../uploads/';
            if (!is_dir($upload_dir)) {
                mkdir($upload_dir, 0777, true);
            }
            $file_extension = pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION);
            $new_filename = uniqid('request_') . '.' . $file_extension;
            if (move_uploaded_file($_FILES['image']['tmp_name'], $upload_dir . $new_filename)) {
                $image_path = 'uploads/' . $new_filename;
            }
        }

        $stmt = $pdo->prepare("
            UPDATE buy_requests 
            SET item_name = :item_name,
                description = :description,
                max_price = :max_price,
                quantity = :quantity,
                item_type = :item_types,
                image = :image
            WHERE id = :request_id AND user_id = :user_id
        ");

        $stmt->execute([
            ':item_name' => $item_name,
            ':description' => $description,
            ':max_price' => $max_price,
            ':quantity' => $quantity,
            ':item_types' => $item_types,
            ':image' => $image_path,
            ':request_id' => $request_id,
            ':user_id' => $_SESSION['user_id']
        ]);

        $_SESSION['success_message'] = "Buy request updated successfully!";
        header("Location: admin_dashboard.php?action=buy_requests");
        exit();
    } catch (PDOException $e) {
        $error = "Error updating buy request: " . $e->getMessage();
    }
}

// At the beginning of the file, add this code to fetch item data
if (isset($_GET['action']) && $_GET['action'] == 'edit_item' && isset($_GET['item_id'])) {
    try {
        $stmt = $pdo->prepare("SELECT * FROM items WHERE id = :item_id AND posted_by = :user_id");
        $stmt->execute([
            ':item_id' => intval($_GET['item_id']),
            ':user_id' => $_SESSION['user_id']
        ]);
        $item_to_edit = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$item_to_edit) {
            $_SESSION['error_message'] = "Item not found or you don't have permission to edit it.";
            header("Location: admin_dashboard.php?action=items_for_sell");
            exit();
        }
    } catch (PDOException $e) {
        $_SESSION['error_message'] = "Error fetching item: " . $e->getMessage();
        header("Location: admin_dashboard.php?action=items_for_sell");
        exit();
    }
}

// Add this where your other form processing code is
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['edit_item_submit'])) {
    try {
        // Validate CSRF token
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            throw new Exception("Invalid CSRF token");
        }

        // Validate required fields
        $required_fields = ['item_id', 'supplier_name', 'item_name', 'description', 'price', 'quantity'];
        foreach ($required_fields as $field) {
            if (!isset($_POST[$field]) || trim($_POST[$field]) === '') {
                throw new Exception("All fields are required");
            }
        }

        // Sanitize and prepare data
        $item_id = intval($_POST['item_id']);
        $supplier_name = sanitizeInput($_POST['supplier_name']);
        $item_name = sanitizeInput($_POST['item_name']);
        $description = sanitizeInput($_POST['description']);
        $price = floatval($_POST['price']);
        $quantity = intval($_POST['quantity']);
        $item_types = sanitizeInput($_POST['item_types'] ?? '');

        // Validate numeric fields
        if ($price <= 0) throw new Exception("Price must be greater than 0");
        if ($quantity < 0) throw new Exception("Quantity cannot be negative");

        // Handle image upload
        $image_path = $_POST['existing_image'] ?? null;
        if (isset($_FILES['image']) && $_FILES['image']['error'] == UPLOAD_ERR_OK) {
            $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
            if (!in_array($_FILES['image']['type'], $allowed_types)) {
                throw new Exception("Invalid file type. Only JPG, PNG and GIF are allowed.");
            }

            $upload_dir = '../uploads/';
            if (!is_dir($upload_dir)) {
                mkdir($upload_dir, 0777, true);
            }

            $file_extension = pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION);
            $new_filename = uniqid('item_') . '.' . $file_extension;
            $full_path = $upload_dir . $new_filename;

            if (!move_uploaded_file($_FILES['image']['tmp_name'], $full_path)) {
                throw new Exception("Failed to upload image");
            }
            $image_path = 'uploads/' . $new_filename;
        }

        // Update the database
        $sql = "UPDATE items SET 
                supplier_name = :supplier_name,
                item_name = :item_name,
                description = :description,
                price = :price,
                quantity = :quantity,
                item_type = :item_types";
        
        if ($image_path !== null) {
            $sql .= ", image = :image";
        }
        
        $sql .= ", updated_at = NOW() 
                WHERE id = :item_id AND posted_by = :user_id";

        $stmt = $pdo->prepare($sql);
        
        $params = [
            ':supplier_name' => $supplier_name,
            ':item_name' => $item_name,
            ':description' => $description,
            ':price' => $price,
            ':quantity' => $quantity,
            ':item_types' => $item_types,
            ':item_id' => $item_id,
            ':user_id' => $_SESSION['user_id']
        ];

        if ($image_path !== null) {
            $params[':image'] = $image_path;
        }

        $stmt->execute($params);

        if ($stmt->rowCount() === 0) {
            throw new Exception("No changes were made or you don't have permission to edit this item");
        }

        $_SESSION['success_message'] = "Item updated successfully!";
        
        // Handle AJAX requests
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            header('Content-Type: application/json');
            echo json_encode(['success' => true, 'message' => 'Item updated successfully']);
            exit;
        }

        // Regular form submission
        header("Location: admin_dashboard.php?action=items_for_sell");
        exit();

    } catch (Exception $e) {
        $_SESSION['error_message'] = $e->getMessage();
        
        // Handle AJAX requests
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            header('Content-Type: application/json');
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
            exit;
        }

        // Regular form submission
        header("Location: admin_dashboard.php?action=items_for_sell");
        exit();
    }
}

// Add this at the beginning of the file after session_start()
if (isset($_GET['action']) && $_GET['action'] == 'items_for_sell') {
    try {
        $stmt = $pdo->prepare("
            SELECT i.*, u.username 
            FROM items i 
            LEFT JOIN users u ON i.posted_by = u.id 
            WHERE i.posted_by = :user_id 
            ORDER BY i.created_at DESC
        ");
        $stmt->execute([':user_id' => $_SESSION['user_id']]);
        $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        $error = "Error fetching items: " . $e->getMessage();
    }
}
?>
<!-- Add this in your items for sale section where you display the items -->
<script>
document.addEventListener('DOMContentLoaded', function() {
    // Handle edit button clicks
    document.querySelectorAll('.edit-item-btn').forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const itemId = this.getAttribute('data-item-id');
            window.location.href = `admin_dashboard.php?action=edit_item&item_id=${itemId}`;
        });
    });

    // Handle edit form submission if it exists
    const editForm = document.getElementById('edit-item-form');
    if (editForm) {
        editForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Show loading state
            const submitButton = this.querySelector('button[type="submit"]');
            const originalText = submitButton.innerHTML;
            submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Updating...';
            submitButton.disabled = true;

            const formData = new FormData(this);

            fetch('admin_dashboard.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Show success message
                    const messageDiv = document.createElement('div');
                    messageDiv.className = 'alert alert-success';
                    messageDiv.textContent = data.message;
                    document.querySelector('.content-wrapper').insertBefore(messageDiv, document.querySelector('.content-wrapper').firstChild);

                    // Redirect after a short delay
                    setTimeout(() => {
                        window.location.href = 'admin_dashboard.php?action=items_for_sell';
                    }, 1000);
                } else {
                    throw new Error(data.message || 'Error updating item');
                }
            })
            .catch(error => {
                // Show error message
                const messageDiv = document.createElement('div');
                messageDiv.className = 'alert alert-danger';
                messageDiv.textContent = error.message;
                document.querySelector('.content-wrapper').insertBefore(messageDiv, document.querySelector('.content-wrapper').firstChild);

                // Reset button
                submitButton.innerHTML = originalText;
                submitButton.disabled = false;
            });
        });
    }

    // Initialize tags input if we're on the edit form
    const tagContainer = document.getElementById('tag-container-edit');
    if (tagContainer) {
        const tagInput = document.getElementById('tag-input-edit');
        const addTagBtn = document.getElementById('add-tag-edit');
        const hiddenInput = document.getElementById('item-types-edit');
        let tags = hiddenInput.value.split(',').filter(tag => tag.trim());

        function renderTags() {
            const wrapper = tagContainer.querySelector('.tag-input-wrapper');
            tagContainer.innerHTML = '';
            tagContainer.appendChild(wrapper);
            tags.forEach(tag => {
                const tagElement = document.createElement('span');
                tagElement.className = 'tag';
                tagElement.innerHTML = `${tag} <span class="remove-tag" data-tag="${tag}">&times;</span>`;
                tagContainer.insertBefore(tagElement, wrapper);
            });
            hiddenInput.value = tags.join(',');
        }

        function addTag(tag) {
            tag = tag.trim();
            if (!tag) return;
            if (tags.includes(tag)) return;
            tags.push(tag);
            renderTags();
            tagInput.value = '';
        }

        renderTags();

        tagInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                addTag(tagInput.value);
            }
        });

        addTagBtn.addEventListener('click', () => {
            addTag(tagInput.value);
        });

        tagContainer.addEventListener('click', (e) => {
            if (e.target.classList.contains('remove-tag')) {
                const tag = e.target.getAttribute('data-tag');
                tags = tags.filter(t => t !== tag);
                renderTags();
            }
        });
    }
});
</script>

<!-- Add this where you want the edit form to appear -->
<?php if (isset($_GET['action']) && $_GET['action'] == 'edit_item' && isset($item_to_edit)): ?>
<div class="edit-form-overlay active"></div>
<div class="edit-form-container active">
    <button class="close-btn" onclick="window.location.href='admin_dashboard.php?action=items_for_sell'">&times;</button>
    <h2><i class="fas fa-edit"></i> Edit Item for Sale</h2>
    <form method="POST" enctype="multipart/form-data" id="edit-item-form">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <input type="hidden" name="item_id" value="<?php echo htmlspecialchars($item_to_edit['id']); ?>">
        <input type="hidden" name="existing_image" value="<?php echo htmlspecialchars($item_to_edit['image'] ?? ''); ?>">

        <div class="form-group">
            <label>Supplier Name</label>
            <input type="text" name="supplier_name" value="<?php echo htmlspecialchars($item_to_edit['supplier_name']); ?>" required class="form-control">
        </div>

        <div class="form-group">
            <label>Item Name</label>
            <input type="text" name="item_name" value="<?php echo htmlspecialchars($item_to_edit['item_name']); ?>" required class="form-control">
        </div>

        <div class="form-group">
            <label>Description</label>
            <textarea name="description" required class="form-control" rows="4"><?php echo htmlspecialchars($item_to_edit['description']); ?></textarea>
        </div>

        <div class="form-group">
            <label>Price ($)</label>
            <input type="number" name="price" value="<?php echo htmlspecialchars($item_to_edit['price']); ?>" step="0.01" required class="form-control">
        </div>

        <div class="form-group">
            <label>Quantity</label>
            <input type="number" name="quantity" value="<?php echo htmlspecialchars($item_to_edit['quantity']); ?>" required class="form-control">
        </div>

        <div class="form-group">
            <label>Item Types</label>
            <div class="tag-container" id="tag-container-edit">
                <div class="tag-input-wrapper">
                    <input type="text" id="tag-input-edit" class="tag-input" placeholder="Type and press Enter or click + to add a type">
                    <button type="button" id="add-tag-edit" class="add-tag-btn">+</button>
                </div>
            </div>
            <input type="hidden" name="item_types" id="item-types-edit" value="<?php echo htmlspecialchars($item_to_edit['item_type']); ?>">
            <div id="tag-error-edit" class="error-text"></div>
        </div>

        <div class="form-group">
            <label>Upload New Image (optional)</label>
            <input type="file" name="image" accept="image/*" class="form-control">
            <?php if (!empty($item_to_edit['image'])): ?>
                <p class="mt-2">Current image: <img src="../<?php echo htmlspecialchars($item_to_edit['image']); ?>" alt="Current Item Image" style="max-width: 100px;"></p>
            <?php endif; ?>
        </div>

        <div class="form-actions">
            <button type="button" class="admin-btn danger" onclick="window.location.href='admin_dashboard.php?action=items_for_sell'">Cancel</button>
            <button type="submit" name="edit_item_submit" class="admin-btn primary">Update Item</button>
        </div>
    </form>
</div>
<?php endif; ?>

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
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 0 20px rgba(0,0,0,0.2);
            z-index: 1000;
            max-width: 90%;
            max-height: 90vh;
            overflow-y: auto;
            width: 600px;
            display: none;
            pointer-events: auto;
        }

        .edit-form-container.active {
            display: block;
        }

        .edit-form-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.5);
            z-index: 999;
            display: none;
            cursor: pointer;
        }

        .edit-form-overlay.active {
            display: block;
        }

        .edit-form-container form {
            max-height: 80vh;
            overflow-y: auto;
            padding-right: 10px;
        }

        .edit-form-container .form-group {
            margin-bottom: 1.5rem;
        }

        .edit-form-container label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: #333;
        }

        .edit-form-container input,
        .edit-form-container textarea,
        .edit-form-container select {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 1rem;
            transition: border-color 0.3s;
        }

        .edit-form-container input:focus,
        .edit-form-container textarea:focus,
        .edit-form-container select:focus {
            border-color: #4CAF50;
            outline: none;
        }

        .edit-form-container .close-btn {
            position: absolute;
            top: 1rem;
            right: 1rem;
            background: none;
            border: none;
            font-size: 1.5rem;
            cursor: pointer;
            color: #666;
            padding: 0.5rem;
            line-height: 1;
        }

        .edit-form-container .close-btn:hover {
            color: #333;
        }

        .edit-form-container .btn-submit {
            background: #4CAF50;
            color: white;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 1rem;
            font-size: 1rem;
            transition: background-color 0.3s;
        }

        .edit-form-container .btn-submit:hover {
            background: #45a049;
        }

        .item-card {
            position: relative;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
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

        .items-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 20px;
            padding: 20px 0;
        }

        .item-card {
            border: 1px solid #e0e0e0;
            overflow: hidden;
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

        .btn-group .btn {
            margin-right: 5px;
            padding: 5px 10px;
            font-size: 14px;
            border-radius: 4px;
            color: white;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }
        
        .btn-group .btn:last-child {
            margin-right: 0;
        }
        
        .btn-info {
            background-color: #17a2b8;
            border-color: #17a2b8;
        }
        
        .btn-info:hover {
            background-color: #138496;
            border-color: #117a8b;
        }
        
        .btn-primary {
            background-color: #007bff;
            border-color: #007bff;
        }
        
        .btn-primary:hover {
            background-color: #0069d9;
            border-color: #0062cc;
        }

        .status-badge.accepted {
            background: #e3f2fd;
            color: #1565c0;
        }

        .report-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .report-section {
            margin: 30px 0;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .report-section h3 {
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }
        
        .table-responsive {
            overflow-x: auto;
        }
        
        .status-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 500;
        }
        
        .status-badge.open {
            background: #e3f2fd;
            color: #1976d2;
        }
        
        .status-badge.closed {
            background: #f8d7da;
            color: #721c24;
        }
        
        .status-badge.accepted {
            background: #d4edda;
            color: #155724;
        }
        
        .status-badge.completed {
            background: #d1ecf1;
            color: #0c5460;
        }

        /* New styles for charts */
        .charts-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin: 20px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }

        .chart-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }

        .chart-title {
            margin-bottom: 15px;
            font-size: 16px;
            font-weight: 600;
            color: #333;
            text-align: center;
        }

        .chart-wrapper {
            position: relative;
            height: 300px;
            width: 100%;
            min-height: 300px;
        }

        .report-filters {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .filter-group {
            margin-bottom: 15px;
        }

        .filter-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: #555;
        }

        .filter-group select,
        .filter-group input {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }

        .report-actions {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }

        .report-actions button {
            padding: 8px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .report-actions button i {
            font-size: 16px;
        }

        .report-actions .btn-primary {
            background: #007bff;
            color: white;
        }

        .report-actions .btn-success {
            background: #28a745;
            color: white;
        }

        .report-actions .btn-info {
            background: #17a2b8;
            color: white;
        }

        .report-actions button:hover {
            opacity: 0.9;
        }

        @media print {
            .sidebar, .navbar, .form-card, .admin-btn, .charts-container {
                display: none !important;
            }
            .report-section {
                break-inside: avoid;
                page-break-inside: avoid;
            }
            .table {
                width: 100% !important;
            }
            .table th, .table td {
                padding: 8px !important;
                font-size: 12px !important;
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
        <?php if (isset($_SESSION['success_message'])): ?>
            <div class="alert alert-success" id="success-alert">
                <?php 
                echo $_SESSION['success_message'];
                unset($_SESSION['success_message']); 
                ?>
            </div>
        <?php endif; ?>

        <?php if (isset($error)): ?>
            <div class="alert alert-error" id="error-alert">
                <?php echo $error; ?>
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
                <form method="POST" enctype="multipart/form-data" style="max-width: 700px; margin: 0 auto;" id="post-sell-form">
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
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Description</label>
                        <textarea name="description" class="input" placeholder="Enter item description" required rows="4" 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50; resize: vertical;"></textarea>
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Price ($)</label>
                        <input type="number" name="price" class="input" placeholder="Enter price" required step="0.01" min="0.01"
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Quantity</label>
                        <input type="number" name="quantity" class="input" placeholder="Enter quantity" required min="1"
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Item Types (e.g., computer chair, marker)</label>
                        <div class="tag-container" id="tag-container-sell">
                            <div class="tag-input-wrapper">
                                <input type="text" id="tag-input-sell" class="tag-input" placeholder="Type and press Enter or click + to add a type"
                                    style="width: calc(100% - 40px); padding: 12px; border: 1px solid #ced4da; border-radius: 8px 0 0 8px; font-size: 14px; background: #fff;">
                                <button type="button" id="add-tag-sell" class="add-tag-btn" style="width: 40px; padding: 12px; border: 1px solid #ced4da; border-left: none; border-radius: 0 8px 8px 0; background: #fff; cursor: pointer;">+</button>
                            </div>
                        </div>
                        <input type="hidden" name="item_types" id="item-types-sell" required>
                        <div id="tag-error-sell" class="error-text" style="color: #dc3545; font-size: 12px; margin-top: 5px; display: none;"></div>
                    </div>

                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Upload Image</label>
                        <input type="file" name="image" accept="image/*" class="input" required
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Close Time (optional)</label>
                        <input type="datetime-local" name="close_time" id="close_time" class="input" 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <div class="form-group" style="text-align: center; margin-top: 20px;">
                        <button type="submit" class="admin-btn primary" style="padding: 12px 30px; font-size: 16px; border-radius: 8px;">
                            <i class="fas fa-upload"></i> Post Item
                        </button>
                    </div>
                </form>
            </div>

            <script>
            document.addEventListener('DOMContentLoaded', function() {
                // Tag Input System for Sell Form
                const sellForm = document.getElementById('post-sell-form');
                if (sellForm) {
                    const tagContainerSell = document.getElementById('tag-container-sell');
                    const tagInputSell = document.getElementById('tag-input-sell');
                    const addTagBtnSell = document.getElementById('add-tag-sell');
                    const hiddenInputSell = document.getElementById('item-types-sell');
                    const tagErrorSell = document.getElementById('tag-error-sell');
                    let tagsSell = [];

                    function renderTagsSell() {
                        const wrapper = tagContainerSell.querySelector('.tag-input-wrapper');
                        tagContainerSell.innerHTML = '';
                        tagContainerSell.appendChild(wrapper);
                        tagsSell.forEach(tag => {
                            const tagElement = document.createElement('span');
                            tagElement.className = 'tag';
                            tagElement.innerHTML = `${tag} <span class="remove-tag" data-tag="${tag}">&times;</span>`;
                            tagContainerSell.insertBefore(tagElement, wrapper);
                        });
                        hiddenInputSell.value = tagsSell.join(',');
                    }

                    function addTagSell(tag) {
                        tag = tag.trim();
                        if (!tag) {
                            tagErrorSell.textContent = 'Tag cannot be empty';
                            tagErrorSell.style.display = 'block';
                            return;
                        }
                        if (tagsSell.includes(tag)) {
                            tagErrorSell.textContent = 'Tag already exists';
                            tagErrorSell.style.display = 'block';
                            return;
                        }
                        tagErrorSell.style.display = 'none';
                        tagsSell.push(tag);
                        renderTagsSell();
                        tagInputSell.value = '';
                    }

                    tagInputSell.addEventListener('keydown', (e) => {
                        if (e.key === 'Enter') {
                            e.preventDefault();
                            addTagSell(tagInputSell.value);
                        }
                    });

                    addTagBtnSell.addEventListener('click', () => {
                        addTagSell(tagInputSell.value);
                    });

                    tagContainerSell.addEventListener('click', (e) => {
                        if (e.target.classList.contains('remove-tag')) {
                            const tag = e.target.getAttribute('data-tag');
                            tagsSell = tagsSell.filter(t => t !== tag);
                            renderTagsSell();
                        }
                    });

                    sellForm.addEventListener('submit', function(e) {
                        if (tagsSell.length === 0) {
                            e.preventDefault();
                            tagErrorSell.textContent = 'Please add at least one item type';
                            tagErrorSell.style.display = 'block';
                            return;
                        }
                        hiddenInputSell.value = tagsSell.join(',');
                    });
                }
            });
            </script>

            <style>
            .tag-container {
                border: 1px solid #ced4da;
                border-radius: 8px;
                padding: 10px;
                background: #fff;
                min-height: 50px;
                margin-bottom: 5px;
            }

            .tag {
                display: inline-block;
                background: #e9ecef;
                padding: 5px 10px;
                border-radius: 15px;
                margin: 2px 5px;
                font-size: 14px;
            }

            .tag .remove-tag {
                cursor: pointer;
                margin-left: 5px;
                color: #dc3545;
            }

            .tag-input-wrapper {
                display: flex;
                margin-top: 10px;
            }

            .add-tag-btn {
                background: #007bff;
                color: white;
                border: none;
                padding: 5px 10px;
                cursor: pointer;
                transition: background-color 0.3s;
            }

            .add-tag-btn:hover {
                background: #0056b3;
            }

            .error-text {
                color: #dc3545;
                font-size: 12px;
                margin-top: 5px;
            }
            </style>

        <?php elseif ($_GET['action'] == 'post_buy'): ?>
            <!-- Post Buy Request Form -->
            <div class="form-card" style="background: #f8f9fa; padding: 25px; border-radius: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: #2c3e50; margin-bottom: 25px; text-align: center; font-size: 24px;"><i class="fas fa-hand-holding-usd"></i> Post Buy Request</h2>
                <form method="POST" enctype="multipart/form-data" style="max-width: 700px; margin: 0 auto;" id="post-buy-form">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Item Name</label>
                        <input type="text" name="item_name" class="input" placeholder="Enter item name" required 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Description</label>
                        <textarea name="description" class="input" placeholder="Enter item description" required rows="4" 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50; resize: vertical;"></textarea>
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Maximum Price ($)</label>
                        <input type="number" name="max_price" class="input" placeholder="Enter maximum price" required step="0.01" min="0.01"
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Quantity</label>
                        <input type="number" name="quantity" class="input" placeholder="Enter quantity" required min="1"
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Item Types (e.g., computer chair, marker)</label>
                        <div class="tag-container" id="tag-container-buy">
                            <div class="tag-input-wrapper">
                                <input type="text" id="tag-input-buy" class="tag-input" placeholder="Type and press Enter or click + to add a type"
                                    style="width: calc(100% - 40px); padding: 12px; border: 1px solid #ced4da; border-radius: 8px 0 0 8px; font-size: 14px; background: #fff;">
                                <button type="button" id="add-tag-buy" class="add-tag-btn" style="width: 40px; padding: 12px; border: 1px solid #ced4da; border-left: none; border-radius: 0 8px 8px 0; background: #fff; cursor: pointer;">+</button>
                            </div>
                        </div>
                        <input type="hidden" name="item_types" id="item-types-buy" required>
                        <div id="tag-error-buy" class="error-text" style="color: #dc3545; font-size: 12px; margin-top: 5px; display: none;"></div>
                    </div>

                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Upload Image (optional)</label>
                        <input type="file" name="image" class="input" accept="image/*" 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Close Time (optional)</label>
                        <input type="datetime-local" name="close_time" class="input" 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>
                    
                    <div class="form-group" style="text-align: center; margin-top: 20px;">
                        <button type="submit" name="post_buy_submit" class="admin-btn primary" style="padding: 12px 30px; font-size: 16px; border-radius: 8px;">
                            <i class="fas fa-upload"></i> Post Buy Request
                        </button>
                    </div>
                </form>
            </div>

            <script>
            document.addEventListener('DOMContentLoaded', function() {
                // Tag Input System for Buy Form
                const buyForm = document.getElementById('post-buy-form');
                if (buyForm) {
                    const tagContainerBuy = document.getElementById('tag-container-buy');
                    const tagInputBuy = document.getElementById('tag-input-buy');
                    const addTagBtnBuy = document.getElementById('add-tag-buy');
                    const hiddenInputBuy = document.getElementById('item-types-buy');
                    const tagErrorBuy = document.getElementById('tag-error-buy');
                    let tagsBuy = [];

                    function renderTagsBuy() {
                        const wrapper = tagContainerBuy.querySelector('.tag-input-wrapper');
                        tagContainerBuy.innerHTML = '';
                        tagContainerBuy.appendChild(wrapper);
                        tagsBuy.forEach(tag => {
                            const tagElement = document.createElement('span');
                            tagElement.className = 'tag';
                            tagElement.innerHTML = `${tag} <span class="remove-tag" data-tag="${tag}">&times;</span>`;
                            tagContainerBuy.insertBefore(tagElement, wrapper);
                        });
                        hiddenInputBuy.value = tagsBuy.join(',');
                    }

                    function addTagBuy(tag) {
                        tag = tag.trim();
                        if (!tag) {
                            tagErrorBuy.textContent = 'Tag cannot be empty';
                            tagErrorBuy.style.display = 'block';
                            return;
                        }
                        if (tagsBuy.includes(tag)) {
                            tagErrorBuy.textContent = 'Tag already exists';
                            tagErrorBuy.style.display = 'block';
                            return;
                        }
                        tagErrorBuy.style.display = 'none';
                        tagsBuy.push(tag);
                        renderTagsBuy();
                        tagInputBuy.value = '';
                    }

                    tagInputBuy.addEventListener('keydown', (e) => {
                        if (e.key === 'Enter') {
                            e.preventDefault();
                            addTagBuy(tagInputBuy.value);
                        }
                    });

                    addTagBtnBuy.addEventListener('click', () => {
                        addTagBuy(tagInputBuy.value);
                    });

                    tagContainerBuy.addEventListener('click', (e) => {
                        if (e.target.classList.contains('remove-tag')) {
                            const tag = e.target.getAttribute('data-tag');
                            tagsBuy = tagsBuy.filter(t => t !== tag);
                            renderTagsBuy();
                        }
                    });

                    buyForm.addEventListener('submit', function(e) {
                        if (tagsBuy.length === 0) {
                            e.preventDefault();
                            tagErrorBuy.textContent = 'Please add at least one item type';
                            tagErrorBuy.style.display = 'block';
                            return;
                        }
                        hiddenInputBuy.value = tagsBuy.join(',');
                    });
                }
            });
            </script>

        <?php elseif ($_GET['action'] == 'items_for_sell'): ?>
            <!-- Items for Sale -->
            <div class="section-title">
                <h2><i class="fas fa-box-open"></i> Items for Sale</h2>
                <a href="?action=post_sell" class="admin-btn primary"><i class="fas fa-plus"></i> Add New Item</a>
            </div>
            
            <?php if (empty($items)): ?>
                <div class="no-items">
                    <p>No items available. <a href="?action=post_sell">Post an item now!</a></p>
                </div>
            <?php else: ?>
                <div class="items-grid">
                    <?php foreach ($items as $item): ?>
                        <div class="item-card <?php echo $item['status'] == 'closed' ? 'closed' : ''; ?>">
                            <div class="card-image">
                                <?php if ($item['image']): ?>
                                    <img src="../<?php echo htmlspecialchars($item['image'], ENT_QUOTES, 'UTF-8'); ?>" alt="<?php echo htmlspecialchars($item['item_name'], ENT_QUOTES, 'UTF-8'); ?>">
                                <?php else: ?>
                                    <img src="../images/placeholder.jpg" alt="No Image">
                                <?php endif; ?>
                                <?php if ($item['status'] == 'closed'): ?>
                                    <span class="card-status">Closed</span>
                                <?php endif; ?>
                            </div>
                            <div class="card-info">
                                <div class="info-row">
                                    <span class="info-label">Item:</span>
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
                                <div class="info-row">
                                    <span class="info-label">Types:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($item['item_type'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <?php if ($item['close_time']): ?>
                                    <div class="info-row">
                                        <span class="info-label">Closes:</span>
                                        <span class="info-value">
                                            <span class="countdown-timer" data-close-time="<?php echo htmlspecialchars($item['close_time'], ENT_QUOTES, 'UTF-8'); ?>">
                                                <i class="fas fa-clock"></i> <span class="time-remaining"></span>
                                            </span>
                                        </span>
                                    </div>
                                <?php endif; ?>
                            </div>
                            <div class="card-actions">
                                <a href="?action=edit_item&item_id=<?php echo $item['id']; ?>" class="admin-btn primary edit-item-btn" data-item-id="<?php echo $item['id']; ?>"><i class="fas fa-edit"></i> Edit</a>
                                <?php if ($item['status'] == 'open'): ?>
                                    <a href="?action=close_item&item_id=<?php echo $item['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to close this item?');"><i class="fas fa-times"></i> Close</a>
                                <?php else: ?>
                                    <a href="?action=open_item&item_id=<?php echo $item['id']; ?>" class="admin-btn success"><i class="fas fa-check"></i> Reopen</a>
                                <?php endif; ?>
                                <a href="?action=delete_item&item_id=<?php echo $item['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this item?');"><i class="fas fa-trash"></i> Delete</a>
                            </div>
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
                                <a href="?action=items_for_sell&page=<?php echo $page - 1; ?>" class="admin-btn primary small"><i class="fas fa-chevron-left"></i> Previous</a>
                            <?php endif; ?>
                            
                            <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                                <a href="?action=items_for_sell&page=<?php echo $i; ?>" class="admin-btn small <?php echo $i == $page ? 'primary' : ''; ?>">
                                    <?php echo $i; ?>
                                </a>
                            <?php endfor; ?>
                            
                            <?php if ($page < $total_pages): ?>
                                <a href="?action=items_for_sell&page=<?php echo $page + 1; ?>" class="admin-btn primary small">Next <i class="fas fa-chevron-right"></i></a>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'buy_requests'): ?>
            <!-- Active Buy Requests -->
            <div class="section-title">
                <h2><i class="fas fa-hand-holding-usd"></i> Active Buy Requests</h2>
                <a href="?action=post_buy" class="admin-btn primary"><i class="fas fa-plus"></i> Add New Request</a>
            </div>
            
            <?php if (empty($requests)): ?>
                <div class="no-items">
                    <p>No buy requests available. <a href="?action=post_buy">Create a buy request now!</a></p>
                </div>
            <?php else: ?>
                <div class="items-grid">
                    <?php foreach ($requests as $request): ?>
                        <div class="item-card <?php echo $request['status'] == 'closed' ? 'closed' : ''; ?>">
                            <div class="card-image">
                                <?php if ($request['image']): ?>
                                    <img src="../<?php echo htmlspecialchars($request['image'], ENT_QUOTES, 'UTF-8'); ?>" alt="<?php echo htmlspecialchars($request['item_name'], ENT_QUOTES, 'UTF-8'); ?>">
                                <?php else: ?>
                                    <img src="../images/placeholder.jpg" alt="No Image">
                                <?php endif; ?>
                                <?php if ($request['status'] == 'closed'): ?>
                                    <span class="card-status">Closed</span>
                                <?php endif; ?>
                            </div>
                            <div class="card-info">
                                <div class="info-row">
                                    <span class="info-label">Item:</span>
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
                                <div class="info-row">
                                    <span class="info-label">Types:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($request['item_type'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <?php if ($request['close_time']): ?>
                                    <div class="info-row">
                                        <span class="info-label">Closes:</span>
                                        <span class="info-value">
                                            <span class="countdown-timer" data-close-time="<?php echo htmlspecialchars($request['close_time'], ENT_QUOTES, 'UTF-8'); ?>">
                                                <i class="fas fa-clock"></i> <span class="time-remaining"></span>
                                            </span>
                                        </span>
                                    </div>
                                <?php endif; ?>
                            </div>
                            <div class="card-actions">
                                <a href="?action=edit_buy_request&request_id=<?php echo $request['id']; ?>" class="admin-btn primary edit-request-btn" data-request-id="<?php echo $request['id']; ?>"><i class="fas fa-edit"></i> Edit</a>
                                <a href="?action=view_offers&request_id=<?php echo $request['id']; ?>" class="admin-btn warning"><i class="fas fa-eye"></i> View Offers</a>
                                <?php if ($request['status'] == 'open'): ?>
                                    <a href="?action=close_buy_request&request_id=<?php echo $request['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to close this buy request?');"><i class="fas fa-times"></i> Close</a>
                                <?php else: ?>
                                    <a href="?action=open_buy_request&request_id=<?php echo $request['id']; ?>" class="admin-btn success"><i class="fas fa-check"></i> Reopen</a>
                                <?php endif; ?>
                                <a href="?action=delete_buy_request&request_id=<?php echo $request['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this buy request?');"><i class="fas fa-trash"></i> Delete</a>
                            </div>
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
                                <a href="?action=buy_requests&page=<?php echo $page - 1; ?>" class="admin-btn primary small"><i class="fas fa-chevron-left"></i> Previous</a>
                            <?php endif; ?>
                            
                            <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                                <a href="?action=buy_requests&page=<?php echo $i; ?>" class="admin-btn small <?php echo $i == $page ? 'primary' : ''; ?>">
                                    <?php echo $i; ?>
                                </a>
                            <?php endfor; ?>
                            
                            <?php if ($page < $total_pages): ?>
                                <a href="?action=buy_requests&page=<?php echo $page + 1; ?>" class="admin-btn primary small">Next <i class="fas fa-chevron-right"></i></a>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'offers'): ?>
            <!-- Offers -->
            <div class="section-title">
                <h2><i class="fas fa-exchange-alt"></i> Offers</h2>
            </div>
            
            <!-- Buy Offers -->
            <h3>Buy Offers (Your Items)</h3>
            <?php if (empty($buy_offers)): ?>
                <div class="no-items">
                    <p>No buy offers available.</p>
                </div>
            <?php else: ?>
                <table class="table">
                    <thead>
                        <tr>
                            <th><a href="?action=offers&buy_sort_field=item_name&buy_sort_order=<?php echo $buy_sort_field == 'item_name' && $buy_sort_order == 'ASC' ? 'DESC' : 'ASC'; ?>">Item Name</a></th>
                            <th><a href="?action=offers&buy_sort_field=offered_price&buy_sort_order=<?php echo $buy_sort_field == 'offered_price' && $buy_sort_order == 'ASC' ? 'DESC' : 'ASC'; ?>">Offered Price</a></th>
                            <th>Quantity</th>
                            <th>User</th>
                            <th><a href="?action=offers&buy_sort_field=created_at&buy_sort_order=<?php echo $buy_sort_field == 'created_at' && $buy_sort_order == 'ASC' ? 'DESC' : 'ASC'; ?>">Date</a></th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($buy_offers as $offer): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($offer['item_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>$<?php echo number_format($offer['offered_price'], 2); ?></td>
                                <td><?php echo htmlspecialchars($offer['quantity'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars($offer['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars($offer['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>
                                    <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=accept" class="admin-btn success" onclick="return confirm('Are you sure you want to accept this offer?');"><i class="fas fa-check"></i> Accept</a>
                                    <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=reject" class="admin-btn danger" onclick="return confirm('Are you sure you want to reject this offer?');"><i class="fas fa-times"></i> Reject</a>
                                    <a href="?action=close_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn warning" onclick="return confirm('Are you sure you want to close this offer?');"><i class="fas fa-ban"></i> Close</a>
                                    <a href="?action=delete_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this offer?');"><i class="fas fa-trash"></i> Delete</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
            
            <!-- Sell Offers -->
            <h3>Sell Offers (Your Buy Requests)</h3>
            <?php if (empty($sell_offers)): ?>
                <div class="no-items">
                    <p>No sell offers available.</p>
                </div>
            <?php else: ?>
                <table class="table">
                    <thead>
                        <tr>
                            <th><a href="?action=offers&sell_sort_field=item_name&sell_sort_order=<?php echo $sell_sort_field == 'item_name' && $sell_sort_order == 'ASC' ? 'DESC' : 'ASC'; ?>">Item Name</a></th>
                            <th><a href="?action=offers&sell_sort_field=offered_price&sell_sort_order=<?php echo $sell_sort_field == 'offered_price' && $sell_sort_order == 'ASC' ? 'DESC' : 'ASC'; ?>">Offered Price</a></th>
                            <th>Quantity</th>
                            <th>User</th>
                            <th><a href="?action=offers&sell_sort_field=created_at&sell_sort_order=<?php echo $sell_sort_field == 'created_at' && $sell_sort_order == 'ASC' ? 'DESC' : 'ASC'; ?>">Date</a></th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($sell_offers as $offer): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($offer['item_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>$<?php echo number_format($offer['offered_price'], 2); ?></td>
                                <td><?php echo htmlspecialchars($offer['quantity'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars($offer['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars($offer['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>
                                    <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=accept" class="admin-btn success" onclick="return confirm('Are you sure you want to accept this offer?');"><i class="fas fa-check"></i> Accept</a>
                                    <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=reject" class="admin-btn danger" onclick="return confirm('Are you sure you want to reject this offer?');"><i class="fas fa-times"></i> Reject</a>
                                    <a href="?action=close_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn warning" onclick="return confirm('Are you sure you want to close this offer?');"><i class="fas fa-ban"></i> Close</a>
                                    <a href="?action=delete_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this offer?');"><i class="fas fa-trash"></i> Delete</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'view_offers' && isset($_GET['request_id'])): ?>
            <!-- View Offers for Buy Request -->
            <div class="section-title">
                <h2><i class="fas fa-exchange-alt"></i> Offers for Buy Request</h2>
                <a href="?action=buy_requests" class="admin-btn primary"><i class="fas fa-arrow-left"></i> Back to Buy Requests</a>
            </div>
            
            <?php if (empty($buy_request_offers)): ?>
                <div class="no-items">
                    <p>No offers available for this buy request.</p>
                </div>
            <?php else: ?>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Item Name</th>
                            <th>Offered Price</th>
                            <th>Quantity</th>
                            <th>User</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($buy_request_offers as $offer): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($offer['item_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>$<?php echo number_format($offer['offered_price'], 2); ?></td>
                                <td><?php echo htmlspecialchars($offer['quantity'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars($offer['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars($offer['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>
                                    <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=accept" class="admin-btn success" onclick="return confirm('Are you sure you want to accept this offer?');"><i class="fas fa-check"></i> Accept</a>
                                    <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=reject" class="admin-btn danger" onclick="return confirm('Are you sure you want to reject this offer?');"><i class="fas fa-times"></i> Reject</a>
                                    <a href="?action=delete_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this offer?');"><i class="fas fa-trash"></i> Delete</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'transactions'): ?>
            <!-- Transactions -->
            <div class="section-title">
                <h2><i class="fas fa-receipt"></i> Transactions</h2>
                <div class="transaction-filters">
                    <form method="GET" class="filter-form">
                        <input type="hidden" name="action" value="transactions">
                        <div class="form-row">
                            <div class="form-group">
                                <label>Date Range</label>
                                <input type="date" name="start_date" value="<?php echo $_GET['start_date'] ?? ''; ?>" class="input">
                                <input type="date" name="end_date" value="<?php echo $_GET['end_date'] ?? ''; ?>" class="input">
                            </div>
                            <div class="form-group">
                                <label>Transaction Type</label>
                                <select name="type" class="input">
                                    <option value="all" <?php echo ($_GET['type'] ?? '') == 'all' ? 'selected' : ''; ?>>All</option>
                                    <option value="sell" <?php echo ($_GET['type'] ?? '') == 'sell' ? 'selected' : ''; ?>>Sell</option>
                                    <option value="buy" <?php echo ($_GET['type'] ?? '') == 'buy' ? 'selected' : ''; ?>>Buy</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Sort By</label>
                                <select name="sort" class="input">
                                    <option value="date_desc" <?php echo ($_GET['sort'] ?? '') == 'date_desc' ? 'selected' : ''; ?>>Date (Newest)</option>
                                    <option value="date_asc" <?php echo ($_GET['sort'] ?? '') == 'date_asc' ? 'selected' : ''; ?>>Date (Oldest)</option>
                                    <option value="amount_desc" <?php echo ($_GET['sort'] ?? '') == 'amount_desc' ? 'selected' : ''; ?>>Amount (High to Low)</option>
                                    <option value="amount_asc" <?php echo ($_GET['sort'] ?? '') == 'amount_asc' ? 'selected' : ''; ?>>Amount (Low to High)</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <button type="submit" class="admin-btn primary"><i class="fas fa-filter"></i> Apply Filters</button>
                                <a href="?action=transactions" class="admin-btn"><i class="fas fa-redo"></i> Reset</a>
                            </div>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Transaction Summary Cards -->
            <div class="transaction-summary">
                <div class="summary-card">
                    <i class="fas fa-dollar-sign"></i>
                    <div class="summary-content">
                        <h3>Total Revenue</h3>
                        <p>$<?php echo number_format($total_revenue ?? 0, 2); ?></p>
                    </div>
                </div>
                <div class="summary-card">
                    <i class="fas fa-shopping-cart"></i>
                    <div class="summary-content">
                        <h3>Total Transactions</h3>
                        <p><?php echo $total_transactions ?? 0; ?></p>
                    </div>
                </div>
                <div class="summary-card">
                    <i class="fas fa-chart-line"></i>
                    <div class="summary-content">
                        <h3>Average Transaction</h3>
                        <p>$<?php echo number_format($average_transaction ?? 0, 2); ?></p>
                    </div>
                </div>
            </div>
            
            <?php if (empty($transactions)): ?>
                <div class="no-items">
                    <p>No transactions available.</p>
                </div>
            <?php else: ?>
                <div class="transaction-table-container">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Transaction ID</th>
                                <th>Item Name</th>
                                <th>Type</th>
                                <th>Buyer</th>
                                <th>Seller</th>
                                <th>Final Price</th>
                                <th>Quantity</th>
                                <th>Total Amount</th>
                                <th>Date</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($transactions as $t): ?>
                                <tr>
                                    <td>#<?php echo str_pad($t['id'], 6, '0', STR_PAD_LEFT); ?></td>
                                    <td><?php echo htmlspecialchars($t['item_name_sell'] ?? $t['item_name_buy'] ?? 'N/A'); ?></td>
                                    <td>
                                        <span class="transaction-type <?php echo $t['item_id'] ? 'sell' : 'buy'; ?>">
                                            <?php echo $t['item_id'] ? 'Sell' : 'Buy'; ?>
                                        </span>
                                    </td>
                                    <td><?php echo htmlspecialchars($t['buyer']); ?></td>
                                    <td><?php echo htmlspecialchars($t['seller'] ?? 'N/A'); ?></td>
                                    <td>$<?php echo number_format($t['final_price'], 2); ?></td>
                                    <td><?php echo htmlspecialchars($t['quantity']); ?></td>
                                    <td>$<?php echo number_format($t['final_price'] * $t['quantity'], 2); ?></td>
                                    <td><?php echo date('M j, Y g:i A', strtotime($t['created_at'])); ?></td>
                                    <td>
                                        <span class="status-badge <?php 
                                            $status = strtolower($t['offer_status'] ?? 'completed');
                                            if ($status == 'completed') echo 'completed';
                                            elseif ($status == 'accepted') echo 'accepted';
                                            elseif ($status == 'pending') echo 'pending';
                                            else echo 'cancelled';
                                        ?>">
                                            <?php echo ucfirst($t['offer_status'] ?? 'Completed'); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <div class="btn-group" role="group">
                                            <button type="button" class="btn btn-sm btn-info" onclick="viewTransactionDetails(<?php echo $t['id']; ?>)">
                                                <i class="fas fa-eye"></i> View
                                            </button>
                                            <a href="print_transaction.php?id=<?php echo $t['id']; ?>" class="btn btn-sm btn-primary" target="_blank">
                                                <i class="fas fa-print"></i> Print
                                            </a>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                
                <!-- Transaction Details Modal -->
                <div class="modal" id="transactionDetailsModal">
                    <div class="modal-content">
                        <span class="close">&times;</span>
                        <h3>Transaction Details</h3>
                        <div id="transactionDetailsContent"></div>
                    </div>
                </div>

                <!-- Pagination -->
                <?php
                $total_pages = ceil($total_transactions / $items_per_page);
                if ($total_pages > 1):
                ?>
                    <div class="pagination">
                        <div class="pagination-links">
                            <?php if ($page > 1): ?>
                                <a href="?action=transactions&page=<?php echo $page - 1; ?>" class="admin-btn primary small">
                                    <i class="fas fa-chevron-left"></i> Previous
                                </a>
                            <?php endif; ?>
                            
                            <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                                <a href="?action=transactions&page=<?php echo $i; ?>" 
                                   class="admin-btn small <?php echo $i == $page ? 'primary' : ''; ?>">
                                    <?php echo $i; ?>
                                </a>
                            <?php endfor; ?>
                            
                            <?php if ($page < $total_pages): ?>
                                <a href="?action=transactions&page=<?php echo $page + 1; ?>" class="admin-btn primary small">
                                    Next <i class="fas fa-chevron-right"></i>
                                </a>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

            <style>
                .transaction-filters {
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 8px;
                    margin-bottom: 20px;
                }
                
                .filter-form {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 15px;
                }
                
                .form-row {
                    display: flex;
                    gap: 15px;
                    width: 100%;
                }
                
                .form-group {
                    flex: 1;
                }
                
                .transaction-summary {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }
                
                .summary-card {
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    display: flex;
                    align-items: center;
                    gap: 15px;
                }
                
                .summary-card i {
                    font-size: 24px;
                    color: #007bff;
                }
                
                .transaction-type {
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: 500;
                }
                
                .transaction-type.sell {
                    background: #e3f2fd;
                    color: #1976d2;
                }
                
                .transaction-type.buy {
                    background: #e8f5e9;
                    color: #2e7d32;
                }
                
                .status-badge {
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: 500;
                }
                
                .status-badge.completed {
                    background: #e8f5e9;
                    color: #2e7d32;
                }
                
                .status-badge.pending {
                    background: #fff3e0;
                    color: #f57c00;
                }
                
                .status-badge.cancelled {
                    background: #ffebee;
                    color: #c62828;
                }
                
                .transaction-table-container {
                    overflow-x: auto;
                }
                
                .modal {
                    display: none;
                    position: fixed;
                    z-index: 1000;
                    left: 0;
                    top: 0;
                    width: 100%;
                    height: 100%;
                    background-color: rgba(0,0,0,0.5);
                }
                
                .modal-content {
                    background-color: white;
                    margin: 5% auto;
                    padding: 20px;
                    border-radius: 8px;
                    width: 80%;
                    max-width: 800px;
                }
                
                .close {
                    color: #aaa;
                    float: right;
                    font-size: 28px;
                    font-weight: bold;
                    cursor: pointer;
                }
            </style>

            <script>
                function viewTransactionDetails(id) {
                    // AJAX call to fetch transaction details
                    fetch(`get_transaction_details.php?id=${id}`)
                        .then(response => response.json())
                        .then(data => {
                            const modal = document.getElementById('transactionDetailsModal');
                            const content = document.getElementById('transactionDetailsContent');
                            
                            content.innerHTML = `
                                <div class="transaction-details">
                                    <div class="detail-row">
                                        <span class="label">Transaction ID:</span>
                                        <span class="value">#${String(id).padStart(6, '0')}</span>
                                    </div>
                                    <div class="detail-row">
                                        <span class="label">Item Name:</span>
                                        <span class="value">${data.item_name}</span>
                                    </div>
                                    <div class="detail-row">
                                        <span class="label">Type:</span>
                                        <span class="value">${data.type}</span>
                                    </div>
                                    <div class="detail-row">
                                        <span class="label">Buyer:</span>
                                        <span class="value">${data.buyer}</span>
                                    </div>
                                    <div class="detail-row">
                                        <span class="label">Seller:</span>
                                        <span class="value">${data.seller}</span>
                                    </div>
                                    <div class="detail-row">
                                        <span class="label">Final Price:</span>
                                        <span class="value">$${data.final_price}</span>
                                    </div>
                                    <div class="detail-row">
                                        <span class="label">Quantity:</span>
                                        <span class="value">${data.quantity}</span>
                                    </div>
                                    <div class="detail-row">
                                        <span class="label">Total Amount:</span>
                                        <span class="value">$${data.total_amount}</span>
                                    </div>
                                    <div class="detail-row">
                                        <span class="label">Date:</span>
                                        <span class="value">${data.date}</span>
                                    </div>
                                    <div class="detail-row">
                                        <span class="label">Status:</span>
                                        <span class="value">${data.status}</span>
                                    </div>
                                </div>
                            `;
                            
                            modal.style.display = "block";
                        });
                }

                function printTransaction(id) {
                    window.open(`print_transaction.php?id=${id}`, '_blank');
                }

                // Close modal when clicking the close button
                document.querySelector('.close').onclick = function() {
                    document.getElementById('transactionDetailsModal').style.display = "none";
                }

                // Close modal when clicking outside
                window.onclick = function(event) {
                    const modal = document.getElementById('transactionDetailsModal');
                    if (event.target == modal) {
                        modal.style.display = "none";
                    }
                }
            </script>

        <?php elseif ($_GET['action'] == 'report'): ?>
            <!-- Reports -->
            <div class="section-title">
                <h2><i class="fas fa-chart-pie"></i> Generate Report</h2>
            </div>
            
            <div class="form-card">
                <h3>Filter Report</h3>
                <form method="POST" action="?action=report&generate_report=1">
                    <div class="form-row">
                        <div class="form-group">
                            <label>Start Date</label>
                            <input type="date" name="start_date" class="input" value="<?php echo $_POST['start_date'] ?? ''; ?>">
                        </div>
                        <div class="form-group">
                            <label>End Date</label>
                            <input type="date" name="end_date" class="input" value="<?php echo $_POST['end_date'] ?? ''; ?>">
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Transaction Type</label>
                            <select name="transaction_type" class="input">
                                <option value="all" <?php echo ($_POST['transaction_type'] ?? '') == 'all' ? 'selected' : ''; ?>>All</option>
                                <option value="sell" <?php echo ($_POST['transaction_type'] ?? '') == 'sell' ? 'selected' : ''; ?>>Sell</option>
                                <option value="buy" <?php echo ($_POST['transaction_type'] ?? '') == 'buy' ? 'selected' : ''; ?>>Buy</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Status</label>
                            <select name="status" class="input">
                                <option value="all" <?php echo ($_POST['status'] ?? '') == 'all' ? 'selected' : ''; ?>>All</option>
                                <option value="open" <?php echo ($_POST['status'] ?? '') == 'open' ? 'selected' : ''; ?>>Open</option>
                                <option value="closed" <?php echo ($_POST['status'] ?? '') == 'closed' ? 'selected' : ''; ?>>Closed</option>
                                <option value="accepted" <?php echo ($_POST['status'] ?? '') == 'accepted' ? 'selected' : ''; ?>>Accepted</option>
                                <option value="completed" <?php echo ($_POST['status'] ?? '') == 'completed' ? 'selected' : ''; ?>>Completed</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Sort By</label>
                            <select name="sort" class="input">
                                <option value="date_desc" <?php echo ($_POST['sort'] ?? '') == 'date_desc' ? 'selected' : ''; ?>>Date (Newest)</option>
                                <option value="date_asc" <?php echo ($_POST['sort'] ?? '') == 'date_asc' ? 'selected' : ''; ?>>Date (Oldest)</option>
                                <option value="amount_desc" <?php echo ($_POST['sort'] ?? '') == 'amount_desc' ? 'selected' : ''; ?>>Amount (High to Low)</option>
                                <option value="amount_asc" <?php echo ($_POST['sort'] ?? '') == 'amount_asc' ? 'selected' : ''; ?>>Amount (Low to High)</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Report Type</label>
                            <select name="report_type" class="input">
                                <option value="all" <?php echo ($_POST['report_type'] ?? '') == 'all' ? 'selected' : ''; ?>>All Reports</option>
                                <option value="transactions" <?php echo ($_POST['report_type'] ?? '') == 'transactions' ? 'selected' : ''; ?>>Transactions Only</option>
                                <option value="inventory" <?php echo ($_POST['report_type'] ?? '') == 'inventory' ? 'selected' : ''; ?>>Inventory Only</option>
                                <option value="buy_requests" <?php echo ($_POST['report_type'] ?? '') == 'buy_requests' ? 'selected' : ''; ?>>Buy Requests Only</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-group">
                        <button type="submit" class="admin-btn primary"><i class="fas fa-search"></i> Generate Report</button>
                        <button type="submit" name="export_csv" value="1" class="admin-btn success"><i class="fas fa-download"></i> Export to CSV</button>
                        <button type="button" class="admin-btn info" onclick="printReport()"><i class="fas fa-print"></i> Print Report</button>
                    </div>
                </form>
            </div>
            
            <?php if (isset($report_transactions) || isset($report_items) || isset($report_requests)): ?>
                <!-- Report Summary -->
                <div class="report-summary">
                    <div class="summary-card">
                        <i class="fas fa-dollar-sign"></i>
                        <div class="summary-content">
                            <h3>Total Revenue</h3>
                            <p>$<?php 
                                $total_revenue = 0;
                                if (isset($report_transactions)) {
                                    foreach ($report_transactions as $t) {
                                        $total_revenue += $t['final_price'] * $t['quantity'];
                                    }
                                }
                                echo number_format($total_revenue, 2); 
                            ?></p>
                        </div>
                    </div>
                    <div class="summary-card">
                        <i class="fas fa-shopping-cart"></i>
                        <div class="summary-content">
                            <h3>Total Transactions</h3>
                            <p><?php echo count($report_transactions ?? []); ?></p>
                        </div>
                    </div>
                    <div class="summary-card">
                        <i class="fas fa-box"></i>
                        <div class="summary-content">
                            <h3>Total Items</h3>
                            <p><?php echo count($report_items ?? []); ?></p>
                        </div>
                    </div>
                    <div class="summary-card">
                        <i class="fas fa-hand-holding-usd"></i>
                        <div class="summary-content">
                            <h3>Total Buy Requests</h3>
                            <p><?php echo count($report_requests ?? []); ?></p>
                        </div>
                    </div>
                </div>

                <!-- Charts Section -->
                <div class="charts-container">
                    <?php if (isset($report_transactions) && !empty($report_transactions)): ?>
                        <div class="chart-card">
                            <div class="chart-title">Transaction Type Distribution</div>
                            <div class="chart-wrapper">
                                <canvas id="transactionTypeChart" width="400" height="300"></canvas>
                            </div>
                        </div>
                        <div class="chart-card">
                            <div class="chart-title">Revenue Over Time</div>
                            <div class="chart-wrapper">
                                <canvas id="revenueChart" width="400" height="300"></canvas>
                            </div>
                        </div>
                    <?php endif; ?>

                    <?php if (isset($report_items) && !empty($report_items)): ?>
                        <div class="chart-card">
                            <div class="chart-title">Inventory Status Distribution</div>
                            <div class="chart-wrapper">
                                <canvas id="inventoryChart" width="400" height="300"></canvas>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>

                <!-- Transactions Report -->
                <?php if (($_POST['report_type'] ?? 'all') == 'all' || ($_POST['report_type'] ?? '') == 'transactions'): ?>
                    <div class="report-section">
                        <h3>Transactions Report</h3>
                        <?php if (empty($report_transactions)): ?>
                            <div class="no-items">
                                <p>No transactions found for the selected criteria.</p>
                            </div>
                        <?php else: ?>
                            <div class="table-responsive">
                                <table class="table">
                                    <thead>
                                        <tr>
                                            <th>Transaction ID</th>
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
                                            <th>Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($report_transactions as $t): ?>
                                            <tr>
                                                <td>#<?php echo str_pad($t['id'], 6, '0', STR_PAD_LEFT); ?></td>
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
                                                <td><?php echo date('M j, Y g:i A', strtotime($t['created_at'])); ?></td>
                                                <td>
                                                    <span class="status-badge <?php echo strtolower($t['offer_status'] ?? 'completed'); ?>">
                                                        <?php echo ucfirst($t['offer_status'] ?? 'Completed'); ?>
                                                    </span>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>

                <!-- Inventory Report -->
                <?php if (($_POST['report_type'] ?? 'all') == 'all' || ($_POST['report_type'] ?? '') == 'inventory'): ?>
                    <div class="report-section">
                        <h3>Inventory Report</h3>
                        <?php if (empty($report_items)): ?>
                            <div class="no-items">
                                <p>No items found for the selected criteria.</p>
                            </div>
                        <?php else: ?>
                            <div class="table-responsive">
                                <table class="table">
                                    <thead>
                                        <tr>
                                            <th>Item ID</th>
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
                                                <td>#<?php echo str_pad($item['id'], 6, '0', STR_PAD_LEFT); ?></td>
                                                <td><?php echo htmlspecialchars($item['item_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                                <td><?php echo htmlspecialchars($item['supplier_name'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
                                                <td><?php echo htmlspecialchars($item['description'], ENT_QUOTES, 'UTF-8'); ?></td>
                                                <td>$<?php echo number_format($item['price'], 2); ?></td>
                                                <td><?php echo htmlspecialchars($item['quantity'], ENT_QUOTES, 'UTF-8'); ?></td>
                                                <td>
                                                    <span class="status-badge <?php echo strtolower($item['status']); ?>">
                                                        <?php echo ucfirst($item['status']); ?>
                                                    </span>
                                                </td>
                                                <td><?php echo htmlspecialchars($item['posted_by_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                                <td><?php echo date('M j, Y g:i A', strtotime($item['created_at'])); ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>

                <!-- Buy Requests Report -->
                <?php if (($_POST['report_type'] ?? 'all') == 'all' || ($_POST['report_type'] ?? '') == 'buy_requests'): ?>
                    <div class="report-section">
                        <h3>Buy Requests Report</h3>
                        <?php if (empty($report_requests)): ?>
                            <div class="no-items">
                                <p>No buy requests found for the selected criteria.</p>
                            </div>
                        <?php else: ?>
                            <div class="table-responsive">
                                <table class="table">
                                    <thead>
                                        <tr>
                                            <th>Request ID</th>
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
                                                <td>#<?php echo str_pad($request['id'], 6, '0', STR_PAD_LEFT); ?></td>
                                                <td><?php echo htmlspecialchars($request['item_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                                <td><?php echo htmlspecialchars($request['description'], ENT_QUOTES, 'UTF-8'); ?></td>
                                                <td>$<?php echo number_format($request['max_price'], 2); ?></td>
                                                <td><?php echo htmlspecialchars($request['quantity'], ENT_QUOTES, 'UTF-8'); ?></td>
                                                <td>
                                                    <span class="status-badge <?php echo strtolower($request['status']); ?>">
                                                        <?php echo ucfirst($request['status']); ?>
                                                    </span>
                                                </td>
                                                <td><?php echo htmlspecialchars($request['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                                                <td><?php echo date('M j, Y g:i A', strtotime($request['created_at'])); ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

            <script>
                function printReport() {
                    window.print();
                }
                
                // Initialize charts when the page loads
                document.addEventListener('DOMContentLoaded', function() {
                    <?php if (isset($report_transactions) && !empty($report_transactions)): ?>
                        // Transaction Type Distribution Chart
                        const transactionTypeCtx = document.getElementById('transactionTypeChart');
                        if (transactionTypeCtx) {
                            const transactionTypeData = {
                                labels: ['Sell', 'Buy'],
                                datasets: [{
                                    data: [
                                        <?php 
                                            $sellCount = 0;
                                            $buyCount = 0;
                                            foreach ($report_transactions as $t) {
                                                if ($t['item_id']) $sellCount++;
                                                else $buyCount++;
                                            }
                                            echo $sellCount . ', ' . $buyCount;
                                        ?>
                                    ],
                                    backgroundColor: ['#007bff', '#28a745'],
                                    borderWidth: 1
                                }]
                            };
                            new Chart(transactionTypeCtx, {
                                type: 'pie',
                                data: transactionTypeData,
                                options: {
                                    responsive: true,
                                    maintainAspectRatio: false,
                                    plugins: {
                                        legend: {
                                            position: 'bottom',
                                            labels: {
                                                padding: 20,
                                                font: {
                                                    size: 12
                                                }
                                            }
                                        },
                                        title: {
                                            display: true,
                                            text: 'Transaction Types',
                                            font: {
                                                size: 16,
                                                weight: 'bold'
                                            }
                                        }
                                    }
                                }
                            });
                        }

                        // Revenue Over Time Chart
                        const revenueCtx = document.getElementById('revenueChart');
                        if (revenueCtx) {
                            const revenueData = {
                                labels: <?php 
                                    $dates = [];
                                    $revenues = [];
                                    foreach ($report_transactions as $t) {
                                        $date = date('M j', strtotime($t['created_at']));
                                        if (!in_array($date, $dates)) {
                                            $dates[] = $date;
                                            $revenues[] = $t['final_price'] * $t['quantity'];
                                        } else {
                                            $revenues[array_search($date, $dates)] += $t['final_price'] * $t['quantity'];
                                        }
                                    }
                                    echo json_encode($dates);
                                ?>,
                                datasets: [{
                                    label: 'Daily Revenue',
                                    data: <?php echo json_encode($revenues); ?>,
                                    borderColor: '#007bff',
                                    backgroundColor: 'rgba(0, 123, 255, 0.1)',
                                    fill: true,
                                    tension: 0.4
                                }]
                            };
                            new Chart(revenueCtx, {
                                type: 'line',
                                data: revenueData,
                                options: {
                                    responsive: true,
                                    maintainAspectRatio: false,
                                    plugins: {
                                        legend: {
                                            position: 'bottom',
                                            labels: {
                                                padding: 20,
                                                font: {
                                                    size: 12
                                                }
                                            }
                                        },
                                        title: {
                                            display: true,
                                            text: 'Revenue Over Time',
                                            font: {
                                                size: 16,
                                                weight: 'bold'
                                            }
                                        }
                                    },
                                    scales: {
                                        y: {
                                            beginAtZero: true,
                                            ticks: {
                                                callback: function(value) {
                                                    return '$' + value.toLocaleString();
                                                }
                                            }
                                        }
                                    }
                                }
                            });
                        }
                    <?php endif; ?>

                    <?php if (isset($report_items) && !empty($report_items)): ?>
                        // Inventory Status Distribution
                        const inventoryCtx = document.getElementById('inventoryChart');
                        if (inventoryCtx) {
                            const inventoryData = {
                                labels: ['Open', 'Closed'],
                                datasets: [{
                                    data: [
                                        <?php 
                                            $openCount = 0;
                                            $closedCount = 0;
                                            foreach ($report_items as $item) {
                                                if ($item['status'] == 'open') $openCount++;
                                                else $closedCount++;
                                            }
                                            echo $openCount . ', ' . $closedCount;
                                        ?>
                                    ],
                                    backgroundColor: ['#28a745', '#dc3545'],
                                    borderWidth: 1
                                }]
                            };
                            new Chart(inventoryCtx, {
                                type: 'doughnut',
                                data: inventoryData,
                                options: {
                                    responsive: true,
                                    maintainAspectRatio: false,
                                    plugins: {
                                        legend: {
                                            position: 'bottom',
                                            labels: {
                                                padding: 20,
                                                font: {
                                                    size: 12
                                                }
                                            }
                                        },
                                        title: {
                                            display: true,
                                            text: 'Inventory Status',
                                            font: {
                                                size: 16,
                                                weight: 'bold'
                                            }
                                        }
                                    }
                                }
                            });
                        }
                    <?php endif; ?>
                });
            </script>
        <?php elseif ($_GET['action'] == 'edit_item' && isset($_GET['item_id'])): ?>
            <div class="edit-form-overlay active"></div>
            <div class="edit-form-container active">
                <button class="close-btn" onclick="window.history.back()">&times;</button>
                <h2><i class="fas fa-edit"></i> Edit Item</h2>
                <form method="POST" enctype="multipart/form-data" id="edit-item-form">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <input type="hidden" name="item_id" value="<?php echo htmlspecialchars($item_to_edit['id']); ?>">
                    <input type="hidden" name="existing_image" value="<?php echo htmlspecialchars($item_to_edit['image'] ?? ''); ?>">

                    <div class="form-group">
                        <label>Supplier Name</label>
                        <input type="text" name="supplier_name" value="<?php echo htmlspecialchars($item_to_edit['supplier_name']); ?>" required class="form-control">
                    </div>

                    <div class="form-group">
                        <label>Item Name</label>
                        <input type="text" name="item_name" value="<?php echo htmlspecialchars($item_to_edit['item_name']); ?>" required class="form-control">
                    </div>

                    <div class="form-group">
                        <label>Description</label>
                        <textarea name="description" required class="form-control" rows="4"><?php echo htmlspecialchars($item_to_edit['description']); ?></textarea>
                    </div>

                    <div class="form-group">
                        <label>Price ($)</label>
                        <input type="number" name="price" value="<?php echo htmlspecialchars($item_to_edit['price']); ?>" step="0.01" required class="form-control">
                    </div>

                    <div class="form-group">
                        <label>Quantity</label>
                        <input type="number" name="quantity" value="<?php echo htmlspecialchars($item_to_edit['quantity']); ?>" required class="form-control">
                    </div>

                    <div class="form-group">
                        <label>Item Types</label>
                        <div class="tag-container" id="tag-container-edit">
                            <div class="tag-input-wrapper">
                                <input type="text" id="tag-input-edit" class="tag-input" placeholder="Type and press Enter or click + to add a type">
                                <button type="button" id="add-tag-edit" class="add-tag-btn">+</button>
                            </div>
                        </div>
                        <input type="hidden" name="item_types" id="item-types-edit" value="<?php echo htmlspecialchars($item_to_edit['item_type']); ?>">
                        <div id="tag-error-edit" class="error-text"></div>
                    </div>

                    <div class="form-group">
                        <label>Upload New Image (optional)</label>
                        <input type="file" name="image" accept="image/*" class="form-control">
                        <?php if (!empty($item_to_edit['image'])): ?>
                            <p class="mt-2">Current image: <img src="../<?php echo htmlspecialchars($item_to_edit['image']); ?>" alt="Current Item Image" style="max-width: 100px;"></p>
                        <?php endif; ?>
                    </div>

                    <div class="form-actions">
                        <button type="button" class="admin-btn danger" onclick="window.history.back()">Cancel</button>
                        <button type="submit" name="edit_item_submit" class="admin-btn primary">Update Item</button>
                    </div>
                </form>
            </div>

            <script>
            document.addEventListener('DOMContentLoaded', function() {
                const form = document.getElementById('edit-item-form');
                const tagInput = document.getElementById('tag-input-edit');
                const addTagBtn = document.getElementById('add-tag-edit');
                const tagContainer = document.getElementById('tag-container-edit');
                const hiddenInput = document.getElementById('item-types-edit');
                let tags = hiddenInput.value.split(',').filter(tag => tag.trim());

                function renderTags() {
                    const wrapper = tagContainer.querySelector('.tag-input-wrapper');
                    tagContainer.innerHTML = '';
                    tagContainer.appendChild(wrapper);
                    tags.forEach(tag => {
                        const tagElement = document.createElement('span');
                        tagElement.className = 'tag';
                        tagElement.innerHTML = `${tag} <span class="remove-tag" data-tag="${tag}">&times;</span>`;
                        tagContainer.insertBefore(tagElement, wrapper);
                    });
                    hiddenInput.value = tags.join(',');
                }

                function addTag(tag) {
                    tag = tag.trim();
                    if (!tag) return;
                    if (tags.includes(tag)) return;
                    tags.push(tag);
                    renderTags();
                    tagInput.value = '';
                }

                renderTags();

                tagInput.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        addTag(tagInput.value);
                    }
                });

                addTagBtn.addEventListener('click', () => {
                    addTag(tagInput.value);
                });

                tagContainer.addEventListener('click', (e) => {
                    if (e.target.classList.contains('remove-tag')) {
                        const tag = e.target.getAttribute('data-tag');
                        tags = tags.filter(t => t !== tag);
                        renderTags();
                    }
                });

                form.addEventListener('submit', function(e) {
                    e.preventDefault();
                    const formData = new FormData(this);

                    fetch(window.location.href, {
                        method: 'POST',
                        body: formData
                    })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error('Network response was not ok');
                        }
                        window.location.href = 'admin_dashboard.php?action=items_for_sell';
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        alert('Error updating item. Please try again.');
                    });
                });
            });
            </script>
        <?php endif; ?>

        <?php if (isset($_GET['action']) && $_GET['action'] == 'edit_buy_request' && isset($request_to_edit)): ?>
            <div class="edit-form-overlay active"></div>
            <div class="edit-form-container active">
                <button class="close-btn" onclick="window.history.back()">&times;</button>
                <h2><i class="fas fa-edit"></i> Edit Buy Request</h2>
                <form method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <input type="hidden" name="request_id" value="<?php echo htmlspecialchars($request_to_edit['id']); ?>">
                    <input type="hidden" name="existing_image" value="<?php echo htmlspecialchars($request_to_edit['image'] ?? ''); ?>">

                    <div class="form-group">
                        <label>Item Name</label>
                        <input type="text" name="item_name" value="<?php echo htmlspecialchars($request_to_edit['item_name']); ?>" required class="form-control">
                    </div>

                    <div class="form-group">
                        <label>Description</label>
                        <textarea name="description" required class="form-control" rows="4"><?php echo htmlspecialchars($request_to_edit['description']); ?></textarea>
                    </div>

                    <div class="form-group">
                        <label>Maximum Price ($)</label>
                        <input type="number" name="max_price" value="<?php echo htmlspecialchars($request_to_edit['max_price']); ?>" step="0.01" required class="form-control">
                    </div>

                    <div class="form-group">
                        <label>Quantity</label>
                        <input type="number" name="quantity" value="<?php echo htmlspecialchars($request_to_edit['quantity']); ?>" required class="form-control">
                    </div>

                    <div class="form-group">
                        <label>Item Types</label>
                        <div class="tag-container" id="tag-container-edit-request">
                            <div class="tag-input-wrapper">
                                <input type="text" id="tag-input-edit-request" class="tag-input" placeholder="Type and press Enter or click + to add a type">
                                <button type="button" id="add-tag-edit-request" class="add-tag-btn">+</button>
                            </div>
                        </div>
                        <input type="hidden" name="item_types" id="item-types-edit-request" value="<?php echo htmlspecialchars($request_to_edit['item_type']); ?>">
                        <div id="tag-error-edit-request" class="error-text"></div>
                    </div>

                    <div class="form-group">
                        <label>Upload New Image (optional)</label>
                        <input type="file" name="image" accept="image/*" class="form-control">
                        <?php if (!empty($request_to_edit['image'])): ?>
                            <p class="mt-2">Current image: <img src="<?php echo htmlspecialchars($request_to_edit['image']); ?>" alt="Current Request Image" style="max-width: 100px;"></p>
                        <?php endif; ?>
                    </div>

                    <div class="form-actions">
                        <button type="button" class="admin-btn danger" onclick="window.history.back()">Cancel</button>
                        <button type="submit" name="edit_request_submit" class="admin-btn primary">Update Request</button>
                    </div>
                </form>
            </div>

            <script>
            // Initialize tags for both forms
            function initializeTags(containerId, inputId, addBtnId, hiddenInputId, initialTags) {
                const container = document.getElementById(containerId);
                const input = document.getElementById(inputId);
                const addBtn = document.getElementById(addBtnId);
                const hiddenInput = document.getElementById(hiddenInputId);
                let tags = initialTags.split(',').filter(tag => tag.trim());

                function renderTags() {
                    const wrapper = container.querySelector('.tag-input-wrapper');
                    container.innerHTML = '';
                    container.appendChild(wrapper);
                    tags.forEach(tag => {
                        const tagElement = document.createElement('span');
                        tagElement.className = 'tag';
                        tagElement.innerHTML = `${tag} <span class="remove-tag" data-tag="${tag}">&times;</span>`;
                        container.insertBefore(tagElement, wrapper);
                    });
                    hiddenInput.value = tags.join(',');
                }

                function addTag(tag) {
                    tag = tag.trim();
                    if (!tag) return;
                    if (tags.includes(tag)) return;
                    tags.push(tag);
                    renderTags();
                    input.value = '';
                }

                renderTags();

                input.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        addTag(input.value);
                    }
                });

                addBtn.addEventListener('click', () => {
                    addTag(input.value);
                });

                container.addEventListener('click', (e) => {
                    if (e.target.classList.contains('remove-tag')) {
                        const tag = e.target.getAttribute('data-tag');
                        tags = tags.filter(t => t !== tag);
                        renderTags();
                    }
                });
            }

            // Initialize tags for item edit form
            if (document.getElementById('tag-container-edit')) {
                initializeTags(
                    'tag-container-edit',
                    'tag-input-edit',
                    'add-tag-edit',
                    'item-types-edit',
                    document.getElementById('item-types-edit').value
                );
            }

            // Initialize tags for request edit form
            if (document.getElementById('tag-container-edit-request')) {
                initializeTags(
                    'tag-container-edit-request',
                    'tag-input-edit-request',
                    'add-tag-edit-request',
                    'item-types-edit-request',
                    document.getElementById('item-types-edit-request').value
                );
            }
            </script>
        <?php endif; ?>
    </div>
</div>

<!-- Edit Item Form Popup -->
<div class="edit-form-overlay" id="edit-form-overlay"></div>
<div class="edit-form-container" id="edit-form-container">
    <div id="edit-form-content"></div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    // Tag Input System for Sell Form
    setupTagInput('sell');
    // Tag Input System for Buy Form
    setupTagInput('buy');

    // Edit Item Form Popup
    document.querySelectorAll('.edit-item-btn').forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const itemId = this.getAttribute('data-item-id');
            fetch(`?action=edit_item&item_id=${itemId}`)
                .then(response => response.text())
                .then(html => {
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(html, 'text/html');
                    const formContent = doc.querySelector('.edit-form-container');
                    if (formContent) {
                        document.getElementById('edit-form-content').innerHTML = formContent.innerHTML;
                        document.getElementById('edit-form-container').classList.add('active');
                        document.getElementById('edit-form-overlay').classList.add('active');
                    }
                })
                .catch(error => console.error('Error loading edit form:', error));
        });
    });

    // Edit Buy Request Form Popup
    document.querySelectorAll('.edit-request-btn').forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const requestId = this.getAttribute('data-request-id');
            fetch(`?action=edit_buy_request&request_id=${requestId}`)
                .then(response => response.text())
                .then(html => {
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(html, 'text/html');
                    const formContent = doc.querySelector('.edit-form-container');
                    if (formContent) {
                        document.getElementById('edit-form-content').innerHTML = formContent.innerHTML;
                        document.getElementById('edit-form-container').classList.add('active');
                        document.getElementById('edit-form-overlay').classList.add('active');
                        setupTagInput('edit-buy', document.getElementById('edit-form-content').querySelector('#item-types-edit'));
                    }
                })
                .catch(error => console.error('Error loading edit form:', error));
        });
    });

    // Close Edit Form
    function closeEditForm() {
        document.getElementById('edit-form-container').classList.remove('active');
        document.getElementById('edit-form-overlay').classList.remove('active');
        document.getElementById('edit-form-content').innerHTML = '';
    }

    document.getElementById('edit-form-overlay').addEventListener('click', closeEditForm);

    // Prevent clicks inside the form from closing it
    document.getElementById('edit-form-container').addEventListener('click', function(e) {
        e.stopPropagation();
    });

    // Countdown Timers
    document.querySelectorAll('.countdown-timer').forEach(timer => {
        const closeTime = new Date(timer.getAttribute('data-close-time')).getTime();
        const updateTimer = () => {
            const now = new Date().getTime();
            const distance = closeTime - now;

            if (distance < 0) {
                timer.classList.add('closed');
                timer.querySelector('.time-remaining').textContent = 'Closed';
                return;
            }

            const days = Math.floor(distance / (1000 * 60 * 60 * 24));
            const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
            const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
            const seconds = Math.floor((distance % (1000 * 60)) / 1000);

            let timeString = '';
            if (days > 0) timeString += `${days}d `;
            if (hours > 0 || days > 0) timeString += `${hours}h `;
            timeString += `${minutes}m ${seconds}s`;

            timer.querySelector('.time-remaining').textContent = timeString;

            if (distance < 24 * 60 * 60 * 1000) {
                timer.classList.add('closing-soon');
            }
        };
        updateTimer();
        setInterval(updateTimer, 1000);
    });

    // Alert Auto-Hide
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.animation = 'slideOut 0.3s ease-in forwards';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });

    // Input Focus Styling
    document.querySelectorAll('.input').forEach(input => {
        input.addEventListener('focus', () => {
            input.style.borderColor = '#48dbfb';
            input.style.boxShadow = '0 0 8px rgba(72, 219, 251, 0.3)';
        });
        input.addEventListener('blur', () => {
            input.style.borderColor = '#ced4da';
            input.style.boxShadow = '0 2px 4px rgba(0,0,0,0.05)';
        });
    });

    // Tag Input System
    function setupTagInput(formType, hiddenInput = null) {
        const prefix = formType === 'sell' ? 'sell' : formType === 'buy' ? 'buy' : 'edit';
        const tagContainer = document.getElementById(`tag-container-${prefix}`);
        const tagInput = document.getElementById(`tag-input-${prefix}`);
        const addTagBtn = document.getElementById(`add-tag-${prefix}`);
        const tagError = document.getElementById(`tag-error-${prefix}`);
        const hiddenTagInput = hiddenInput || document.getElementById(`item-types-${prefix}`);
        let tags = hiddenTagInput && hiddenTagInput.value ? hiddenTagInput.value.split(',').filter(tag => tag.trim()) : [];

        function renderTags() {
            const tagWrapper = tagContainer.querySelector('.tag-input-wrapper');
            tagContainer.innerHTML = '';
            tagContainer.appendChild(tagWrapper);
            tags.forEach(tag => {
                const tagElement = document.createElement('span');
                tagElement.className = 'tag';
                tagElement.innerHTML = `${tag} <span class="remove-tag" data-tag="${tag}">&times;</span>`;
                tagContainer.insertBefore(tagElement, tagWrapper);
            });
            updateHiddenTags(prefix);
        }

        function addTag(tag) {
            tag = tag.trim();
            if (!tag) {
                tagError.textContent = 'Tag cannot be empty.';
                tagError.style.display = 'block';
                return false;
            }
            if (tags.includes(tag)) {
                tagError.textContent = 'This tag already exists.';
                tagError.style.display = 'block';
                return false;
            }
            if (tag.length > 50) {
                tagError.textContent = 'Tag is too long (max 50 characters).';
                tagError.style.display = 'block';
                return false;
            }
            tags.push(tag);
            tagError.style.display = 'none';
            renderTags();
            return true;
        }

        if (tagInput) {
            tagInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    if (addTag(tagInput.value)) {
                        tagInput.value = '';
                    }
                }
            });

            addTagBtn.addEventListener('click', () => {
                if (addTag(tagInput.value)) {
                    tagInput.value = '';
                }
            });

            tagContainer.addEventListener('click', (e) => {
                if (e.target.classList.contains('remove-tag')) {
                    const tag = e.target.getAttribute('data-tag');
                    tags = tags.filter(t => t !== tag);
                    renderTags();
                }
            });

            renderTags();
        }
    }

    window.updateHiddenTags = function(prefix) {
        const hiddenTagInput = document.getElementById(`item-types-${prefix}`);
        const tags = Array.from(document.getElementById(`tag-container-${prefix}`).querySelectorAll('.tag'))
            .map(tag => tag.textContent.replace(/\s*×$/, '').trim())
            .filter(tag => tag);
        hiddenTagInput.value = tags.join(',');
        return tags.length > 0;
    };
});
</script>

<style>
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
</style>

</body>
</html>