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
                        $upload_dir = '../uploads/';
                        if (!file_exists($upload_dir)) {
                            mkdir($upload_dir, 0777, true);
                        }
                        $image_path = $upload_dir . uniqid() . '_' . $filename;
                        move_uploaded_file($_FILES['image']['tmp_name'], $image_path);
                    }
                }

                if (!isset($error)) {
                    $stmt = $pdo->prepare("INSERT INTO items_for_sale (supplier_name, item_name, item_type, description, price, quantity, status, image, close_time, created_at) VALUES (:supplier_name, :item_name, :item_type, :description, :price, :quantity, 'available', :image, :close_time, NOW())");
                    $stmt->execute([
                        ':supplier_name' => $supplier_name,
                        ':item_name' => $item_name,
                        ':item_type' => $item_types,
                        ':description' => $description,
                        ':price' => $price,
                        ':quantity' => $quantity,
                        ':image' => $image_path,
                        ':close_time' => $close_time
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
                        $upload_dir = '../uploads/';
                        if (!file_exists($upload_dir)) {
                            mkdir($upload_dir, 0777, true);
                        }
                        $image_path = $upload_dir . uniqid() . '_' . $filename;
                        move_uploaded_file($_FILES['image']['tmp_name'], $image_path);
                    }
                }

                if (!isset($error)) {
                    $stmt = $pdo->prepare("INSERT INTO buy_requests (item_name, item_type, description, max_price, quantity, status, image, close_time, created_at) VALUES (:item_name, :item_type, :description, :max_price, :quantity, 'open', :image, :close_time, NOW())");
                    $stmt->execute([
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

// Handle Close/Open Item
if (isset($_GET['action']) && ($_GET['action'] == 'close_item' || $_GET['action'] == 'open_item') && isset($_GET['item_id'])) {
    $item_id = intval($_GET['item_id']);
    $new_status = $_GET['action'] == 'close_item' ? 'closed' : 'open';
    try {
        // Verify the item exists and belongs to the admin
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
        // Verify the buy request exists and belongs to the admin
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
            max-height: 80vh;
            overflow-y: auto;
            -webkit-overflow-scrolling: touch;
        }

        .edit-form-container.active {
            display: block;
        }

        .edit-form-container form {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }

        .edit-form-container .form-group {
            margin-bottom: 0;
        }

        .edit-form-container .form-group label {
            font-weight: 500;
            color: #2c3e50;
            margin-bottom: 5px;
            display: block;
        }

        .edit-form-container .form-group input,
        .edit-form-container .form-group textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ced4da;
            border-radius: 8px;
            font-size: 14px;
            color: #2c3e50;
        }

        .edit-form-container .form-actions {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
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

        /* Edit Form Styles */
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
        }

        .edit-form-container .form-group {
            margin-bottom: 1rem;
        }

        .edit-form-container label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }

        .edit-form-container input,
        .edit-form-container textarea,
        .edit-form-container select {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid #ddd;
            border-radius: 4px;
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
        }

        .edit-form-container .close-btn:hover {
            color: #333;
        }

        .edit-form-container .btn-submit {
            background: #4CAF50;
            color: white;
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 1rem;
        }

        .edit-form-container .btn-submit:hover {
            background: #45a049;
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
                    
                                       <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Upload Image (optional)</label>
                        <input type="file" name="image" class="input" accept="image/jpeg,image/png,image/gif" 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>

                    <button type="submit" class="admin-btn primary" 
                        style="width: 100%; padding: 12px; font-size: 16px; font-weight: 500; background: #007bff; color: white; border: none; border-radius: 8px; transition: background 0.3s ease; cursor: pointer;">
                        Post Item for Sale
                    </button>
                </form>
            </div>

            <script>
                // Tag input functionality for sell form
                const tagContainerSell = document.getElementById('tag-container-sell');
                const tagInputSell = document.getElementById('tag-input-sell');
                const addTagButtonSell = document.getElementById('add-tag-sell');
                const hiddenTagsSell = document.getElementById('item-types-sell');
                const tagErrorSell = document.getElementById('tag-error-sell');
                let tagsSell = [];

                function addTagSell(tag) {
                    if (tag && !tagsSell.includes(tag)) {
                        tagsSell.push(tag);
                        const tagElement = document.createElement('span');
                        tagElement.className = 'tag';
                        tagElement.innerHTML = `${tag} <span class="remove-tag" data-tag="${tag}">×</span>`;
                        tagContainerSell.insertBefore(tagElement, tagInputSell.parentElement);
                        tagInputSell.value = '';
                        updateHiddenTags('item-types-sell');
                    }
                }

                function updateHiddenTags(inputId) {
                    const hiddenInput = document.getElementById(inputId);
                    const tags = inputId === 'item-types-sell' ? tagsSell : tagsBuy;
                    hiddenInput.value = tags.join(',');
                    if (tags.length === 0) {
                        const errorElement = inputId === 'item-types-sell' ? tagErrorSell : tagErrorBuy;
                        errorElement.textContent = 'Please add at least one item type.';
                        errorElement.style.display = 'block';
                        return false;
                    }
                    const errorElement = inputId === 'item-types-sell' ? tagErrorSell : tagErrorBuy;
                    errorElement.style.display = 'none';
                    return true;
                }

                addTagButtonSell.addEventListener('click', () => {
                    const tag = tagInputSell.value.trim();
                    if (tag) addTagSell(tag);
                });

                tagInputSell.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        const tag = tagInputSell.value.trim();
                        if (tag) addTagSell(tag);
                    }
                });

                tagContainerSell.addEventListener('click', (e) => {
                    if (e.target.classList.contains('remove-tag')) {
                        const tag = e.target.getAttribute('data-tag');
                        tagsSell = tagsSell.filter(t => t !== tag);
                        e.target.parentElement.remove();
                        updateHiddenTags('item-types-sell');
                    }
                });

                // Tag input functionality for buy form
                const tagContainerBuy = document.getElementById('tag-container-buy');
                const tagInputBuy = document.getElementById('tag-input-buy');
                const addTagButtonBuy = document.getElementById('add-tag-buy');
                const hiddenTagsBuy = document.getElementById('item-types-buy');
                const tagErrorBuy = document.getElementById('tag-error-buy');
                let tagsBuy = [];

                function addTagBuy(tag) {
                    if (tag && !tagsBuy.includes(tag)) {
                        tagsBuy.push(tag);
                        const tagElement = document.createElement('span');
                        tagElement.className = 'tag';
                        tagElement.innerHTML = `${tag} <span class="remove-tag" data-tag="${tag}">×</span>`;
                        tagContainerBuy.insertBefore(tagElement, tagInputBuy.parentElement);
                        tagInputBuy.value = '';
                        updateHiddenTags('item-types-buy');
                    }
                }

                addTagButtonBuy.addEventListener('click', () => {
                    const tag = tagInputBuy.value.trim();
                    if (tag) addTagBuy(tag);
                });

                tagInputBuy.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        const tag = tagInputBuy.value.trim();
                        if (tag) addTagBuy(tag);
                    }
                });

                tagContainerBuy.addEventListener('click', (e) => {
                    if (e.target.classList.contains('remove-tag')) {
                        const tag = e.target.getAttribute('data-tag');
                        tagsBuy = tagsBuy.filter(t => t !== tag);
                        e.target.parentElement.remove();
                        updateHiddenTags('item-types-buy');
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
                    <p>No items available. Start by adding a new item!</p>
                    <a href="?action=post_sell" class="admin-btn primary">Add Item</a>
                </div>
            <?php else: ?>
                <div class="items-grid">
                    <?php foreach ($items as $item): ?>
                        <div class="item-card <?php echo $item['status'] == 'closed' ? 'closed' : ''; ?>">
                            <?php if ($item['status'] == 'closed'): ?>
                                <div class="card-status">Closed</div>
                            <?php endif; ?>
                            <div class="card-image">
                                <img src="<?php echo !empty($item['image']) ? htmlspecialchars($item['image'], ENT_QUOTES, 'UTF-8') : '../img/placeholder.jpg'; ?>" alt="Item Image">
                            </div>
                            <div class="card-info">
                                <div class="info-row">
                                    <span class="info-label">Item Name:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($item['item_name'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Supplier:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($item['supplier_name'], ENT_QUOTES, 'UTF-8'); ?></span>
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
                                    <span class="info-label">Status:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($item['status'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <?php if ($item['close_time']): ?>
                                    <div class="info-row">
                                        <span class="info-label">Closes:</span>
                                        <span class="countdown-timer" data-close-time="<?php echo htmlspecialchars($item['close_time'], ENT_QUOTES, 'UTF-8'); ?>">
                                            <?php
                                            $closeTime = strtotime($item['close_time']);
                                            $now = time();
                                            if ($closeTime > $now) {
                                                $diff = $closeTime - $now;
                                                $days = floor($diff / (60 * 60 * 24));
                                                $hours = floor(($diff % (60 * 60 * 24)) / (60 * 60));
                                                $minutes = floor(($diff % (60 * 60)) / 60);
                                                echo "$days"."d $hours"."h $minutes"."m";
                                            } else {
                                                echo "Closed";
                                            }
                                            ?>
                                        </span>
                                    </div>
                                <?php endif; ?>
                            </div>
                            <div class="card-actions">
                                <a href="?action=edit_item&item_id=<?php echo $item['id']; ?>" class="admin-btn primary edit-item-btn"><i class="fas fa-edit"></i> Edit</a>
                                <?php if ($item['status'] == 'open'): ?>
                                    <a href="?action=close_item&item_id=<?php echo $item['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to close this item?');"><i class="fas fa-times"></i> Close</a>
                                <?php else: ?>
                                    <a href="?action=open_item&item_id=<?php echo $item['id']; ?>" class="admin-btn success"><i class="fas fa-check"></i> Reopen</a>
                                <?php endif; ?>
                                <a href="?action=delete_item&item_id=<?php echo $item['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this item? This will also delete related offers and transactions.');"><i class="fas fa-trash"></i> Delete</a>
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
                <a href="?action=post_buy" class="admin-btn primary"><i class="fas fa-plus"></i> Add New Request</a>
            </div>

            <?php if (empty($requests)): ?>
                <div class="no-items">
                    <p>No buy requests available. Start by creating a new request!</p>
                    <a href="?action=post_buy" class="admin-btn primary">Add Buy Request</a>
                </div>
            <?php else: ?>
                <div class="items-grid">
                    <?php foreach ($requests as $request): ?>
                        <div class="item-card <?php echo $request['status'] == 'closed' ? 'closed' : ''; ?>">
                            <?php if ($request['status'] == 'closed'): ?>
                                <div class="card-status">Closed</div>
                            <?php endif; ?>
                            <div class="card-image">
                                <img src="<?php echo !empty($request['image']) ? htmlspecialchars($request['image'], ENT_QUOTES, 'UTF-8') : '../img/placeholder.jpg'; ?>" alt="Request Image">
                            </div>
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
                                <div class="info-row">
                                    <span class="info-label">Status:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($request['status'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <?php if ($request['close_time']): ?>
                                    <div class="info-row">
                                        <span class="info-label">Closes:</span>
                                        <span class="countdown-timer" data-close-time="<?php echo htmlspecialchars($request['close_time'], ENT_QUOTES, 'UTF-8'); ?>">
                                            <?php
                                            $closeTime = strtotime($request['close_time']);
                                            $now = time();
                                            if ($closeTime > $now) {
                                                $diff = $closeTime - $now;
                                                $days = floor($diff / (60 * 60 * 24));
                                                $hours = floor(($diff % (60 * 60 * 24)) / (60 * 60));
                                                $minutes = floor(($diff % (60 * 60)) / 60);
                                                echo "$days"."d $hours"."h $minutes"."m";
                                            } else {
                                                echo "Closed";
                                            }
                                            ?>
                                        </span>
                                    </div>
                                <?php endif; ?>
                            </div>
                            <div class="card-actions">
                                <a href="?action=edit_buy_request&request_id=<?php echo $request['id']; ?>" class="admin-btn primary edit-buy-request-btn"><i class="fas fa-edit"></i> Edit</a>
                                <?php if ($request['status'] == 'open'): ?>
                                    <a href="?action=close_buy_request&request_id=<?php echo $request['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to close this buy request?');"><i class="fas fa-times"></i> Close</a>
                                <?php else: ?>
                                    <a href="?action=open_buy_request&request_id=<?php echo $request['id']; ?>" class="admin-btn success"><i class="fas fa-check"></i> Reopen</a>
                                <?php endif; ?>
                                <a href="?action=delete_buy_request&request_id=<?php echo $request['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this buy request? This will also delete related offers and transactions.');"><i class="fas fa-trash"></i> Delete</a>
                                <a href="?action=view_offers&request_id=<?php echo $request['id']; ?>" class="admin-btn primary"><i class="fas fa-eye"></i> View Offers</a>
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

        <?php elseif ($_GET['action'] == 'edit_item' && isset($item_to_edit)): ?>
            <!-- Edit Item Form -->
            <div class="overlay active"></div>
            <div class="edit-form-container active">
                <h2 style="color: #2c3e50; margin-bottom: 20px; text-align: center;"><i class="fas fa-edit"></i> Edit Item</h2>
                <form method="POST" enctype="multipart/form-data" onsubmit="return updateHiddenTags('item-types-edit')">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="existing_image" value="<?php echo htmlspecialchars($item_to_edit['image'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">

                    <div class="form-group">
                        <label>Supplier Name</label>
                        <input type="text" name="supplier_name" value="<?php echo htmlspecialchars($item_to_edit['supplier_name'], ENT_QUOTES, 'UTF-8'); ?>" required />
                    </div>

                    <div class="form-group">
                        <label>Item Name</label>
                        <input type="text" name="item_name" value="<?php echo htmlspecialchars($item_to_edit['item_name'], ENT_QUOTES, 'UTF-8'); ?>" required />
                    </div>

                    <div class="form-group">
                        <label>Item Types</label>
                        <div class="tag-container" id="tag-container-edit">
                            <div class="tag-input-wrapper">
                                <input type="text" id="tag-input-edit" class="tag-input" placeholder="Type and press Enter or click + to add a type">
                                <button type="button" id="add-tag-edit" class="add-tag-btn">+</button>
                            </div>
                            <div id="tag-error-edit" class="error-text"></div>
                        </div>
                        <input type="hidden" name="item_types" id="item-types-edit">
                    </div>

                    <div class="form-group">
                        <label>Description</label>
                        <textarea name="description" rows="4" required><?php echo htmlspecialchars($item_to_edit['description'], ENT_QUOTES, 'UTF-8'); ?></textarea>
                    </div>

                    <div class="form-group">
                        <label>Price ($)</label>
                        <input type="number" name="price" value="<?php echo htmlspecialchars($item_to_edit['price'], ENT_QUOTES, 'UTF-8'); ?>" step="0.01" required />
                    </div>

                    <div class="form-group">
                        <label>Quantity</label>
                        <input type="number" name="quantity" value="<?php echo htmlspecialchars($item_to_edit['quantity'], ENT_QUOTES, 'UTF-8'); ?>" required />
                    </div>

                    <div class="form-group">
                        <label>Close Time (optional)</label>
                        <input type="datetime-local" name="close_time" value="<?php echo $item_to_edit['close_time'] ? date('Y-m-d\TH:i', strtotime($item_to_edit['close_time'])) : ''; ?>" />
                    </div>

                    <div class="form-group">
                        <label>Upload New Image (optional)</label>
                        <input type="file" name="image" accept="image/jpeg,image/png,image/gif" />
                        <?php if ($item_to_edit['image']): ?>
                            <p>Current Image: <img src="<?php echo htmlspecialchars($item_to_edit['image'], ENT_QUOTES, 'UTF-8'); ?>" alt="Current Image" style="max-width: 100px; margin-top: 10px;"></p>
                        <?php endif; ?>
                    </div>

                    <div class="form-actions">
                        <button type="button" class="admin-btn danger close-edit-form">Cancel</button>
                        <button type="submit" class="admin-btn primary">Update Item</button>
                    </div>
                </form>
            </div>

            <script>
                // Preload existing tags for edit form
                let tagsEdit = <?php echo json_encode(explode(',', $item_to_edit['item_type'] ?? '')); ?>.filter(tag => tag.trim());
                const tagContainerEdit = document.getElementById('tag-container-edit');
                const tagInputEdit = document.getElementById('tag-input-edit');
                const addTagButtonEdit = document.getElementById('add-tag-edit');
                const hiddenTagsEdit = document.getElementById('item-types-edit');
                const tagErrorEdit = document.getElementById('tag-error-edit');

                function addTagEdit(tag) {
                    tag = tag.trim();
                    if (tag && !tagsEdit.includes(tag)) {
                        tagsEdit.push(tag);
                        const tagElement = document.createElement('span');
                        tagElement.className = 'tag';
                        tagElement.innerHTML = `${tag} <span class="remove-tag" data-tag="${tag}">×</span>`;
                        tagContainerEdit.insertBefore(tagElement, tagInputEdit.parentElement);
                        tagInputEdit.value = '';
                        updateHiddenTags('item-types-edit');
                    }
                }

                // Load existing tags
                tagsEdit.forEach(tag => {
                    if (tag.trim()) {
                        const tagElement = document.createElement('span');
                        tagElement.className = 'tag';
                        tagElement.innerHTML = `${tag} <span class="remove-tag" data-tag="${tag}">×</span>`;
                        tagContainerEdit.insertBefore(tagElement, tagInputEdit.parentElement);
                    }
                });
                updateHiddenTags('item-types-edit');

                addTagButtonEdit.addEventListener('click', () => {
                    const tag = tagInputEdit.value.trim();
                    if (tag) addTagEdit(tag);
                });

                tagInputEdit.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        const tag = tagInputEdit.value.trim();
                        if (tag) addTagEdit(tag);
                    }
                });

                tagContainerEdit.addEventListener('click', (e) => {
                    if (e.target.classList.contains('remove-tag')) {
                        const tag = e.target.getAttribute('data-tag');
                        tagsEdit = tagsEdit.filter(t => t !== tag);
                        e.target.parentElement.remove();
                        updateHiddenTags('item-types-edit');
                    }
                });
            </script>

        <?php elseif ($_GET['action'] == 'edit_buy_request' && isset($request_to_edit)): ?>
            <!-- Edit Buy Request Form -->
            <div class="overlay active"></div>
            <div class="edit-form-container active">
                <h2 style="color: #2c3e50; margin-bottom: 20px; text-align: center;"><i class="fas fa-edit"></i> Edit Buy Request</h2>
                <form method="POST" enctype="multipart/form-data" onsubmit="return updateHiddenTags('item-types-edit-buy')">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="existing_image" value="<?php echo htmlspecialchars($request_to_edit['image'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">

                    <div class="form-group">
                        <label>Item Name</label>
                        <input type="text" name="item_name" value="<?php echo htmlspecialchars($request_to_edit['item_name'], ENT_QUOTES, 'UTF-8'); ?>" required />
                    </div>

                    <div class="form-group">
                        <label>Item Types</label>
                        <div class="tag-container" id="tag-container-edit-buy">
                            <div class="tag-input-wrapper">
                                <input type="text" id="tag-input-edit-buy" class="tag-input" placeholder="Type and press Enter or click + to add a type">
                                <button type="button" id="add-tag-edit-buy" class="add-tag-btn">+</button>
                            </div>
                            <div id="tag-error-edit-buy" class="error-text"></div>
                        </div>
                        <input type="hidden" name="item_types" id="item-types-edit-buy">
                    </div>

                    <div class="form-group">
                        <label>Description</label>
                        <textarea name="description" rows="4" required><?php echo htmlspecialchars($request_to_edit['description'], ENT_QUOTES, 'UTF-8'); ?></textarea>
                    </div>

                    <div class="form-group">
                        <label>Max Price ($)</label>
                        <input type="number" name="max_price" value="<?php echo htmlspecialchars($request_to_edit['max_price'], ENT_QUOTES, 'UTF-8'); ?>" step="0.01" required />
                    </div>

                    <div class="form-group">
                        <label>Quantity</label>
                        <input type="number" name="quantity" value="<?php echo htmlspecialchars($request_to_edit['quantity'], ENT_QUOTES, 'UTF-8'); ?>" required />
                    </div>

                    <div class="form-group">
                        <label>Close Time (optional)</label>
                        <input type="datetime-local" name="close_time" value="<?php echo $request_to_edit['close_time'] ? date('Y-m-d\TH:i', strtotime($request_to_edit['close_time'])) : ''; ?>" />
                    </div>

                    <div class="form-group">
                        <label>Upload New Image (optional)</label>
                        <input type="file" name="image" accept="image/jpeg,image/png,image/gif" />
                        <?php if ($request_to_edit['image']): ?>
                            <p>Current Image: <img src="<?php echo htmlspecialchars($request_to_edit['image'], ENT_QUOTES, 'UTF-8'); ?>" alt="Current Image" style="max-width: 100px; margin-top: 10px;"></p>
                        <?php endif; ?>
                    </div>

                    <div class="form-actions">
                        <button type="button" class="admin-btn danger close-edit-form">Cancel</button>
                        <button type="submit" class="admin-btn primary">Update Buy Request</button>
                    </div>
                </form>
            </div>

            <script>
                // Preload existing tags for edit buy request form
                let tagsEditBuy = <?php echo json_encode(explode(',', $request_to_edit['item_type'] ?? '')); ?>.filter(tag => tag.trim());
                const tagContainerEditBuy = document.getElementById('tag-container-edit-buy');
                const tagInputEditBuy = document.getElementById('tag-input-edit-buy');
                const addTagButtonEditBuy = document.getElementById('add-tag-edit-buy');
                const hiddenTagsEditBuy = document.getElementById('item-types-edit-buy');
                const tagErrorEditBuy = document.getElementById('tag-error-edit-buy');

                function addTagEditBuy(tag) {
                    tag = tag.trim();
                    if (tag && !tagsEditBuy.includes(tag)) {
                        tagsEditBuy.push(tag);
                        const tagElement = document.createElement('span');
                        tagElement.className = 'tag';
                        tagElement.innerHTML = `${tag} <span class="remove-tag" data-tag="${tag}">×</span>`;
                        tagContainerEditBuy.insertBefore(tagElement, tagInputEditBuy.parentElement);
                        tagInputEditBuy.value = '';
                        updateHiddenTags('item-types-edit-buy');
                    }
                }

                // Load existing tags
                tagsEditBuy.forEach(tag => {
                    if (tag.trim()) {
                        const tagElement = document.createElement('span');
                        tagElement.className = 'tag';
                        tagElement.innerHTML = `${tag} <span class="remove-tag" data-tag="${tag}">×</span>`;
                        tagContainerEditBuy.insertBefore(tagElement, tagInputEditBuy.parentElement);
                    }
                });
                updateHiddenTags('item-types-edit-buy');

                addTagButtonEditBuy.addEventListener('click', () => {
                    const tag = tagInputEditBuy.value.trim();
                    if (tag) addTagEditBuy(tag);
                });

                tagInputEditBuy.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        const tag = tagInputEditBuy.value.trim();
                        if (tag) addTagEditBuy(tag);
                    }
                });

                tagContainerEditBuy.addEventListener('click', (e) => {
                    if (e.target.classList.contains('remove-tag')) {
                        const tag = e.target.getAttribute('data-tag');
                        tagsEditBuy = tagsEditBuy.filter(t => t !== tag);
                        e.target.parentElement.remove();
                        updateHiddenTags('item-types-edit-buy');
                    }
                });
            </script>

        <?php elseif ($_GET['action'] == 'view_offers' && isset($buy_request_offers)): ?>
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
                <div class="items-grid">
                    <?php foreach ($buy_request_offers as $offer): ?>
                        <div class="item-card">
                            <div class="card-info">
                                <div class="info-row">
                                    <span class="info-label">Item Name:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($offer['item_name'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Offered By:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($offer['username'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Offered Price:</span>
                                    <span class="info-value">$<?php echo number_format($offer['offered_price'], 2); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Quantity:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($offer['quantity'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Total:</span>
                                    <span class="info-value">$<?php echo number_format($offer['offered_price'] * $offer['quantity'], 2); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Date:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($offer['created_at'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                            </div>
                            <div class="card-actions">
                                <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=accept" class="admin-btn success" onclick="return confirm('Are you sure you want to accept this offer?');"><i class="fas fa-check"></i> Accept</a>
                                <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=reject" class="admin-btn danger" onclick="return confirm('Are you sure you want to reject this offer?');"><i class="fas fa-times"></i> Reject</a>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'offers'): ?>
            <!-- Offers Section -->
            <div class="section-title">
                <h2><i class="fas fa-exchange-alt"></i> Pending Offers</h2>
            </div>

            <h3>Offers on Your Items</h3>
            <?php if (empty($buy_offers)): ?>
                <div class="no-items">
                    <p>No pending offers on your items.</p>
                </div>
            <?php else: ?>
                <div class="items-grid">
                    <?php foreach ($buy_offers as $offer): ?>
                        <div class="item-card">
                            <div class="card-info">
                                <div class="info-row">
                                    <span class="info-label">Item Name:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($offer['item_name'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Offered By:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($offer['username'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Offered Price:</span>
                                    <span class="info-value">$<?php echo number_format($offer['offered_price'], 2); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Quantity:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($offer['quantity'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Total:</span>
                                    <span class="info-value">$<?php echo number_format($offer['offered_price'] * $offer['quantity'], 2); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Date:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($offer['created_at'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                            </div>
                            <div class="card-actions">
                                <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=accept" class="admin-btn success" onclick="return confirm('Are you sure you want to accept this offer?');"><i class="fas fa-check"></i> Accept</a>
                                <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=reject" class="admin-btn danger" onclick="return confirm('Are you sure you want to reject this offer?');"><i class="fas fa-times"></i> Reject</a>
                                <a href="?action=delete_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this offer?');"><i class="fas fa-trash"></i> Delete</a>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <h3>Offers on Your Buy Requests</h3>
            <?php if (empty($sell_offers)): ?>
                <div class="no-items">
                    <p>No pending offers on your buy requests.</p>
                </div>
            <?php else: ?>
                <div class="items-grid">
                    <?php foreach ($sell_offers as $offer): ?>
                        <div class="item-card">
                            <div class="card-info">
                                <div class="info-row">
                                    <span class="info-label">Item Name:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($offer['item_name'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Offered By:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($offer['username'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Offered Price:</span>
                                    <span class="info-value">$<?php echo number_format($offer['offered_price'], 2); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Quantity:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($offer['quantity'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Total:</span>
                                    <span class="info-value">$<?php echo number_format($offer['offered_price'] * $offer['quantity'], 2); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Date:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($offer['created_at'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                            </div>
                            <div class="card-actions">
                                <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=accept" class="admin-btn success" onclick="return confirm('Are you sure you want to accept this offer?');"><i class="fas fa-check"></i> Accept</a>
                                <a href="?action=offer_action&offer_id=<?php echo $offer['id']; ?>&type=reject" class="admin-btn danger" onclick="return confirm('Are you sure you want to reject this offer?');"><i class="fas fa-times"></i> Reject</a>
                                <a href="?action=delete_offer&offer_id=<?php echo $offer['id']; ?>" class="admin-btn danger" onclick="return confirm('Are you sure you want to delete this offer?');"><i class="fas fa-trash"></i> Delete</a>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

        <?php elseif ($_GET['action'] == 'transactions'): ?>
            <!-- Transactions Section -->
            <div class="section-title">
                <h2><i class="fas fa-receipt"></i> Transactions</h2>
            </div>

            <?php if (empty($transactions)): ?>
                <div class="no-items">
                    <p>No transactions available.</p>
                </div>
            <?php else: ?>
                <div class="items-grid">
                    <?php foreach ($transactions as $transaction): ?>
                        <div class="item-card">
                            <div class="card-info">
                                <div class="info-row">
                                    <span class="info-label">Item Name:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($transaction['item_name_sell'] ?? $transaction['item_name_buy'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Type:</span>
                                    <span class="info-value"><?php echo $transaction['item_id'] ? 'Sell' : 'Buy'; ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Buyer:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($transaction['buyer'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Seller:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($transaction['seller'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Final Price:</span>
                                    <span class="info-value">$<?php echo number_format($transaction['final_price'], 2); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Quantity:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($transaction['quantity'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Total Amount:</span>
                                    <span class="info-value">$<?php echo number_format($transaction['final_price'] * $transaction['quantity'], 2); ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Date:</span>
                                    <span class="info-value"><?php echo htmlspecialchars($transaction['created_at'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>

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
            <!-- Reports Section -->
            <div class="section-title">
                <h2><i class="fas fa-chart-pie"></i> Generate Reports</h2>
            </div>

            <div class="form-card">
                <h3>Filter Report</h3>
                <form method="POST" action="?action=report&generate_report=1">
                    <div class="form-row" style="display: flex; gap: 15px; margin-bottom: 15px;">
                        <div class="form-group" style="flex: 1;">
                            <label>Start Date</label>
                            <input type="date" name="start_date" class="input" />
                        </div>
                        <div class="form-group" style="flex: 1;">
                            <label>End Date</label>
                            <input type="date" name="end_date" class="input" />
                        </div>
                    </div>
                    <div class="form-row" style="display: flex; gap: 15px; margin-bottom: 15px;">
                        <div class="form-group" style="flex: 1;">
                            <label>Transaction Type</label>
                            <select name="transaction_type" class="input">
                                <option value="all">All</option>
                                <option value="sell">Sell</option>
                                <option value="buy">Buy</option>
                            </select>
                        </div>
                        <div class="form-group" style="flex: 1;">
                            <label>Status</label>
                            <select name="status" class="input">
                                <option value="all">All</option>
                                <option value="open">Open</option>
                                <option value="closed">Closed</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-actions">
                        <button type="submit" name="generate" class="admin-btn primary">Generate Report</button>
                        <button type="submit" name="export_csv" class="admin-btn success">Export to CSV</button>
                    </div>
                </form>
            </div>

            <?php if (isset($report_transactions)): ?>
                <h3>Transactions Report</h3>
                <?php if (empty($report_transactions)): ?>
                    <div class="no-items">
                        <p>No transactions match your criteria.</p>
                    </div>
                <?php else: ?>
                    <div class="items-grid">
                        <?php foreach ($report_transactions as $transaction): ?>
                            <div class="item-card">
                                <div class="card-info">
                                    <div class="info-row">
                                        <span class="info-label">Item Name:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($transaction['item_name_sell'] ?? $transaction['item_name_buy'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Type:</span>
                                        <span class="info-value"><?php echo $transaction['item_id'] ? 'Sell' : 'Buy'; ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Buyer:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($transaction['buyer'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Seller:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($transaction['seller'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Final Price:</span>
                                        <span class="info-value">$<?php echo number_format($transaction['final_price'], 2); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Quantity:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($transaction['quantity'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Total Amount:</span>
                                        <span class="info-value">$<?php echo number_format($transaction['final_price'] * $transaction['quantity'], 2); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Date:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($transaction['created_at'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>

                <h3>Inventory Report</h3>
                <?php if (empty($report_items)): ?>
                    <div class="no-items">
                        <p>No items match your criteria.</p>
                    </div>
                <?php else: ?>
                    <div class="items-grid">
                        <?php foreach ($report_items as $item): ?>
                            <div class="item-card <?php echo $item['status'] == 'closed' ? 'closed' : ''; ?>">
                                <div class="card-info">
                                    <div class="info-row">
                                        <span class="info-label">Item Name:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($item['item_name'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Supplier:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($item['supplier_name'], ENT_QUOTES, 'UTF-8'); ?></span>
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
                                        <span class="info-label">Status:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($item['status'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Posted By:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($item['posted_by_name'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Created At:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($item['created_at'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>

                <h3>Buy Requests Report</h3>
                <?php if (empty($report_requests)): ?>
                    <div class="no-items">
                        <p>No buy requests match your criteria.</p>
                    </div>
                <?php else: ?>
                    <div class="items-grid">
                        <?php foreach ($report_requests as $request): ?>
                            <div class="item-card <?php echo $request['status'] == 'closed' ? 'closed' : ''; ?>">
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
                                    <div class="info-row">
                                        <span class="info-label">Status:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($request['status'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">User:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($request['username'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">Created At:</span>
                                        <span class="info-value"><?php echo htmlspecialchars($request['created_at'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            <?php endif; ?>
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
                        <input type="datetime-local" name="close_time" id="close_time_buy" class="input" 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>

                    <div class="form-group" style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #2c3e50; font-weight: 500;">Upload Image (optional)</label>
                        <input type="file" name="image" class="input" accept="image/jpeg,image/png,image/gif" 
                            style="width: 100%; padding: 12px; border: 1px solid #ced4da; border-radius: 8px; font-size: 14px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.3s ease; color: #2c3e50;" />
                    </div>

                    <button type="submit" class="admin-btn primary" 
                        style="width: 100%; padding: 12px; font-size: 16px; font-weight: 500; background: #007bff; color: white; border: none; border-radius: 8px; transition: background 0.3s ease; cursor: pointer;">
                        Post Buy Request
                    </button>
                </form>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- Footer -->
<footer class="footer">
    <div class="inner-width">
        <p>&copy; 2025 Online Bidding System | All Rights Reserved</p>
    </div>
</footer>

<script>
    // Countdown timer updates
    function updateCountdown() {
        document.querySelectorAll('.countdown-timer').forEach(timer => {
            const closeTime = new Date(timer.getAttribute('data-close-time')).getTime();
            const now = new Date().getTime();
            const diff = closeTime - now;

            if (diff <= 0) {
                timer.textContent = 'Closed';
                timer.classList.add('closed');
            } else {
                const days = Math.floor(diff / (1000 * 60 * 60 * 24));
                const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
                timer.textContent = `${days}d ${hours}h ${minutes}m`;
                if (diff < 24 * 60 * 60 * 1000) {
                    timer.classList.add('closing-soon');
                }
            }
        });
    }
    setInterval(updateCountdown, 60000); // Update every minute
    updateCountdown(); // Initial update

    // Edit form handling
    const editButtons = document.querySelectorAll('.edit-item-btn, .edit-buy-request-btn');
    const closeButtons = document.querySelectorAll('.close-edit-form');
    const overlay = document.querySelector('.overlay');
    const editFormContainer = document.querySelector('.edit-form-container');

    editButtons.forEach(button => {
        button.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = button.getAttribute('href');
        });
    });

    closeButtons.forEach(button => {
        button.addEventListener('click', () => {
            window.history.back();
        });
    });

    // Alerts auto-dismiss
    setTimeout(() => {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(alert => alert.remove());
    }, 5000);
</script>

<script>
document.addEventListener('DOMContentLoaded', function() {
    // Toggle sections
    const toggleButtons = document.querySelectorAll('.toggle-section');
    
    toggleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const section = document.getElementById(targetId);
            const overlay = document.querySelector(`.overlay[data-target="${targetId}"]`);
            
            if (section && overlay) {
                const isOpen = section.style.display === 'block';
                
                // Toggle section
                section.style.display = isOpen ? 'none' : 'block';
                
                // Toggle overlay
                overlay.style.display = isOpen ? 'none' : 'block';
                
                // Update button text and icon
                const icon = this.querySelector('i');
                if (icon) {
                    icon.className = isOpen ? 'fas fa-chevron-down' : 'fas fa-chevron-up';
                }
                this.querySelector('span').textContent = isOpen ? 'Open' : 'Close';
            }
        });
    });
});
</script>

<script>
// ... existing toggle code ...

// Edit form functionality
function showEditForm(requestId, type) {
    const overlay = document.createElement('div');
    overlay.className = 'edit-form-overlay';
    document.body.appendChild(overlay);
    
    const formContainer = document.createElement('div');
    formContainer.className = 'edit-form-container';
    formContainer.innerHTML = `
        <button class="close-btn">&times;</button>
        <h2>Edit ${type === 'sale' ? 'Item' : 'Request'}</h2>
        <form id="editForm">
            <div class="form-group">
                <label for="title">Title</label>
                <input type="text" id="title" name="title" required>
            </div>
            <div class="form-group">
                <label for="description">Description</label>
                <textarea id="description" name="description" required></textarea>
            </div>
            <div class="form-group">
                <label for="price">${type === 'sale' ? 'Price' : 'Budget'}</label>
                <input type="number" id="price" name="price" required>
            </div>
            <div class="form-group">
                <label for="status">Status</label>
                <select id="status" name="status" required>
                    <option value="active">Active</option>
                    <option value="inactive">Inactive</option>
                </select>
            </div>
            <button type="submit" class="btn-submit">Save Changes</button>
        </form>
    `;
    
    document.body.appendChild(formContainer);
    
    // Fetch and populate data
    fetch(`get_request_data.php?id=${requestId}&type=${type}`)
        .then(response => response.json())
        .then(data => {
            document.getElementById('title').value = data.title;
            document.getElementById('description').value = data.description;
            document.getElementById('price').value = data.price;
            document.getElementById('status').value = data.status;
        })
        .catch(error => console.error('Error:', error));
    
    // Close button functionality
    formContainer.querySelector('.close-btn').addEventListener('click', () => {
        document.body.removeChild(overlay);
        document.body.removeChild(formContainer);
    });
    
    // Form submission
    formContainer.querySelector('form').addEventListener('submit', (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        formData.append('id', requestId);
        formData.append('type', type);
        
        fetch('update_request.php', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Error updating: ' + data.message);
            }
        })
        .catch(error => console.error('Error:', error));
    });
    
    // Show overlay and form
    overlay.style.display = 'block';
}

// Add click handlers to edit buttons
document.querySelectorAll('.edit-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        const requestId = this.getAttribute('data-id');
        const type = this.getAttribute('data-type');
        showEditForm(requestId, type);
    });
});
</script>

<script>
// Tag system for buy form
const tagContainerBuy = document.getElementById('tag-container-buy');
const tagInputBuy = document.getElementById('tag-input-buy');
const addTagBtnBuy = document.getElementById('add-tag-buy');
const tagErrorBuy = document.getElementById('tag-error-buy');
const itemTypesBuy = document.getElementById('item-types-buy');
let tagsBuy = [];

// Add tag function for buy form
function addTagBuy() {
    const tag = tagInputBuy.value.trim();
    if (tag) {
        if (tagsBuy.includes(tag)) {
            tagErrorBuy.textContent = 'This type is already added';
            tagErrorBuy.style.display = 'block';
            return;
        }
        tagsBuy.push(tag);
        const tagElement = document.createElement('div');
        tagElement.className = 'tag';
        tagElement.innerHTML = `
            <span>${tag}</span>
            <button type="button" class="remove-tag">&times;</button>
        `;
        tagContainerBuy.insertBefore(tagElement, tagContainerBuy.firstChild);
        tagInputBuy.value = '';
        tagErrorBuy.style.display = 'none';
        updateHiddenTagsBuy();
    }
}

// Update hidden input for buy form
function updateHiddenTagsBuy() {
    itemTypesBuy.value = JSON.stringify(tagsBuy);
}

// Event listeners for buy form
addTagBtnBuy.addEventListener('click', addTagBuy);
tagInputBuy.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        addTagBuy();
    }
});

tagContainerBuy.addEventListener('click', (e) => {
    if (e.target.classList.contains('remove-tag')) {
        const tagElement = e.target.parentElement;
        const tag = tagElement.querySelector('span').textContent;
        tagsBuy = tagsBuy.filter(t => t !== tag);
        tagElement.remove();
        updateHiddenTagsBuy();
    }
});

document.querySelector('form[onsubmit="return updateHiddenTags(\'item-types-buy\')"]').addEventListener('submit', function(e) {
    if (tagsBuy.length === 0) {
        e.preventDefault();
        tagErrorBuy.textContent = 'Please add at least one item type';
        tagErrorBuy.style.display = 'block';
        return false;
    }
    updateHiddenTagsBuy();
    return true;
});
</script>

</body>
</html>