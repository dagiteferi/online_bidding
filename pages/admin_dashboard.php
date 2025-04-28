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
                        $upload_dir = dirname(__DIR__) . '/Uploads/';
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
                br.description AS description Rust
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
                            #2c3e50;" />
                    </div>
                    
                    <div class="form-group" style="text-align: center; margin-top: 20px;">
                        <button type="submit" class="admin-btn primary" style="padding: 12px 30px; font-size: 16px; border-radius: 8px;">
                            <i class="fas fa-upload"></i> Post Item
                        </button>
                    </div>
                </form>
            </div>

        <?php elseif ($_GET['action'] == 'post_buy'): ?>
            <!-- Post Buy Request Form -->
            <div class="form-card" style="background: #f8f9fa; padding: 25px; border-radius: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: #2c3e50; margin-bottom: 25px; text-align: center; font-size: 24px;"><i class="fas fa-hand-holding-usd"></i> Post Buy Request</h2>
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
                            <input type="number" name="max_price" class="input" placeholder="Enter maximum price" step="0.01" required 
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
                    
                    <div class="form-group" style="text-align: center; margin-top: 20px;">
                        <button type="submit" class="admin-btn primary" style="padding: 12px 30px; font-size: 16px; border-radius: 8px;">
                            <i class="fas fa-upload"></i> Post Buy Request
                        </button>
                    </div>
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
            </div>
            
            <?php if (empty($transactions)): ?>
                <div class="no-items">
                    <p>No transactions available.</p>
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
                                <a href="?action=transactions&page=<?php echo $page - 1; ?>" class="admin-btn primary small"><i class="fas fa-chevron-left"></i> Previous</a>
                            <?php endif; ?>
                            
                            <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                                <a href="?action=transactions&page=<?php echo $i; ?>" class="admin-btn small <?php echo $i == $page ? 'primary' : ''; ?>">
                                    <?php echo $i; ?>
                                </a>
                            <?php endfor; ?>
                            
                            <?php if ($page < $total_pages): ?>
                                <a href="?action=transactions&page=<?php echo $page + 1; ?>" class="admin-btn primary small">Next <i class="fas fa-chevron-right"></i></a>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

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
                                <option value="sell">Sell</option>
                                <option value="buy">Buy</option>
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
                    <div class="form-group">
                        <button type="submit" class="admin-btn primary"><i class="fas fa-search"></i> Generate Report</button>
                        <button type="submit" name="export_csv" value="1" class="admin-btn success"><i class="fas fa-download"></i> Export to CSV</button>
                    </div>
                </form>
            </div>
            
            <?php if (isset($report_transactions) || isset($report_items) || isset($report_requests)): ?>
                <!-- Transactions Report -->
                <h3>Transactions</h3>
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
                
                <!-- Inventory Report -->
                <h3>Inventory</h3>
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
                
                <!-- Buy Requests Report -->
                <h3>Buy Requests</h3>
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

        <?php elseif ($_GET['action'] == 'edit_item' && isset($_GET['item_id'])): ?>
            <div class="edit-form-overlay active"></div>
            <div class="edit-form-container active">
                <button class="close-btn" onclick="window.history.back()">&times;</button>
                <h2><i class="fas fa-edit"></i> Edit Item</h2>
                <form method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
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
                            <p class="mt-2">Current image: <img src="<?php echo htmlspecialchars($item_to_edit['image']); ?>" alt="Current Item Image" style="max-width: 100px;"></p>
                        <?php endif; ?>
                    </div>

                    <div class="form-actions">
                        <button type="button" class="admin-btn danger" onclick="window.history.back()">Cancel</button>
                        <button type="submit" class="admin-btn primary">Update Item</button>
                    </div>
                </form>
            </div>

            <script>
            // Initialize tags for edit form
            const tagsEdit = <?php echo json_encode(explode(',', $item_to_edit['item_type'])); ?>.filter(tag => tag.trim());
            const tagContainerEdit = document.getElementById('tag-container-edit');
            const tagInputEdit = document.getElementById('tag-input-edit');
            const addTagButtonEdit = document.getElementById('add-tag-edit');
            const hiddenTagsEdit = document.getElementById('item-types-edit');
            const tagErrorEdit = document.getElementById('tag-error-edit');

            function renderTagsEdit() {
                const tagWrapper = tagContainerEdit.querySelector('.tag-input-wrapper');
                tagContainerEdit.innerHTML = '';
                tagContainerEdit.appendChild(tagWrapper);
                tagsEdit.forEach(tag => {
                    const tagElement = document.createElement('span');
                    tagElement.className = 'tag';
                    tagElement.innerHTML = `${tag} <span class="remove-tag" data-tag="${tag}">&times;</span>`;
                    tagContainerEdit.insertBefore(tagElement, tagWrapper);
                });
                hiddenTagsEdit.value = tagsEdit.join(',');
            }

            function addTagEdit(tag) {
                tag = tag.trim();
                if (!tag) {
                    tagErrorEdit.textContent = 'Tag cannot be empty';
                    tagErrorEdit.style.display = 'block';
                    return;
                }
                if (tagsEdit.includes(tag)) {
                    tagErrorEdit.textContent = 'Tag already exists';
                    tagErrorEdit.style.display = 'block';
                    return;
                }
                tagErrorEdit.style.display = 'none';
                tagsEdit.push(tag);
                renderTagsEdit();
                tagInputEdit.value = '';
            }

            renderTagsEdit();

            tagInputEdit.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    addTagEdit(tagInputEdit.value);
                }
            });

            addTagButtonEdit.addEventListener('click', () => {
                addTagEdit(tagInputEdit.value);
            });

            tagContainerEdit.addEventListener('click', (e) => {
                if (e.target.classList.contains('remove-tag')) {
                    const tag = e.target.getAttribute('data-tag');
                    const index = tagsEdit.indexOf(tag);
                    if (index > -1) {
                        tagsEdit.splice(index, 1);
                        renderTagsEdit();
                    }
                }
            });
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