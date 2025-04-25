

<?php
/**
 * Database Connection and Table Management
 * 
 * This file handles the database connection and ensures required tables exist.
 * It uses PDO for secure database operations and includes error handling.
 * 
 * Database Structure:
 * 
 * 1. items table (for items posted for sale):
 *    - id: Auto-incrementing primary key
 *    - posted_by: User ID of the person posting the item
 *    - supplier_name: Name of the supplier/vendor
 *    - item_name: Name of the item being sold
 *    - description: Detailed description of the item
 *    - price: Selling price of the item
 *    - quantity: Available quantity
 *    - status: Current status (open/closed)
 *    - created_at: Timestamp of when the item was posted
 *    - user_id: Foreign key to users table
 *    - image: Path to item image
 *    - title: Alternative name for the item
 *    - item_type: Category/type of the item
 *    - closing_time: Scheduled closing time
 *    - close_time: Actual closing time
 * 
 * 2. buy_requests table (for items users want to buy):
 *    - id: Auto-incrementing primary key
 *    - user_id: User ID of the person making the request
 *    - item_name: Name of the requested item
 *    - item_type: Category/type of the item
 *    - description: Detailed description of the request
 *    - max_price: Maximum price willing to pay
 *    - quantity: Desired quantity
 *    - created_at: Timestamp of when the request was made
 *    - status: Current status (open/closed)
 *    - image: Path to reference image
 *    - closing_time: Scheduled closing time
 *    - close_time: Actual closing time
 * 
 * 3. item_types table (for managing item categories):
 *    - id: Auto-incrementing primary key
 *    - type_name: Name of the item type (unique)
 *    - created_at: Timestamp of when the type was added
 * 
 * @author Your Name
 * @version 1.0
 * @package OnlineBidding
 */

// Database connection parameters
$host = 'localhost';
$dbname = 'online_bidding';
$username = 'root'; 
$password = ''; 

try {
    // Create PDO connection with error handling
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    /**
     * Create item_types table if it doesn't exist
     * This table stores the different categories/types of items that can be posted
     * It helps in organizing and filtering items in the system
     */
    $pdo->exec("CREATE TABLE IF NOT EXISTS item_types (
        id INT AUTO_INCREMENT PRIMARY KEY,
        type_name VARCHAR(255) NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )");
} catch (PDOException $e) {
    // Log the error and terminate the script
    error_log("Database connection failed: " . $e->getMessage());
    die("Connection failed: " . $e->getMessage());
}
?>