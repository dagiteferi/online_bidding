<?php
// This page handles user logout functionality.
session_start();
session_destroy();
header("Location: index.php");
exit();
?>