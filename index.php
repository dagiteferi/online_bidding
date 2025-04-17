<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" type="text/css" href="css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="javaScript/scripts.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Ubuntu:ital,wght@0,300;0,400;0,500;0,700;1,300;1,400;1,500;1,700&display=swap" rel="stylesheet">
    <title>Online Bidding Platform</title>
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
                <a href="index.php">Home</a>
                <a href="#about">About</a>
                <a href="#contact">Contact</a>
                <a href="pages/login.php">Login</a>
            </div>
        </div>
    </nav>

    <!-- Home Section -->
    <section id="home">
        <div class="inner-width">
            <div class="content">
                <div class="front">
                    <div class="front-child1">
                        <h1 style="font-size:35px">
                            Online Bidding Platform
                            <span class="">Bid Smart, Win Big!</span>
                        </h1>
                        <div class="front-child1">
                            <div class="buttons">
                                <a href="pages/login.php">Login</a>
                                <a href="pages/register.php">Register</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Steps Section -->
    <div class="step">
        <div class="step-main-cont1">
            <p>Steps</p>
            <img src="img/hr.svg" alt="">
            <h1>How It Works</h1>
        </div>
        <div class="step-main-cont2">
            <div class="step1-cont">
                <img class="select" src="img/register.png" alt="">
                <h6>Register</h6>
                <p>Create an account to start bidding or selling items.</p>
            </div>
            <div class="step2-cont">
                <img class="operat" src="img/browse.png" alt="">
                <h6>Browse Items</h6>
                <p>Explore a wide range of products up for auction.</p>
            </div>
            <div class="step3-cont">
                <img class="dri" src="img/bid.png" alt="">
                <h6>Place Bids</h6>
                <p>Bid on your favorite items and win the auction!</p>
            </div>
        </div>
    </div>

    <!-- About Section -->
    <section id="about">
        <div class="inner-width">
            <h2>About Us</h2>
            <p>Welcome to our Online Bidding Platform, where buyers and sellers connect to trade unique items through exciting auctions. Our mission is to provide a secure, user-friendly environment for bidding and selling, ensuring transparency and fairness.</p>
            <ul>
                <li>Wide range of products, from electronics to collectibles.</li>
                <li>Secure payment and bidding processes.</li>
                <li>Support for both buyers and sellers to maximize value.</li>
            </ul>
            <p>Developed by Group 8, we’re passionate about revolutionizing online auctions!</p>
        </div>
    </section>

    <!-- Contact Section -->
    <section id="contact">
        <div class="inner-width">
            <h2>Contact Us</h2>
            <p>Have questions or need assistance? Reach out to us!</p>
            <p>Email: <a href="mailto:support@onlinebidding.com">support@onlinebidding.com</a></p>
            <p>Follow us on social media:</p>
            <div class="sm">
                <a href="#/"><i class="fa fa-facebook" style="font-size:24px"></i></a>
                <a href="#/"><i class="fa fa-instagram" style="font-size:24px"></i></a>
                <a href="#/"><i class="fa fa-linkedin" style="font-size:24px"></i></a>
                <a href="#"><i class="fa fa-telegram" style="font-size:24px"></i></a>
                <a href="#"><i class="fa fa-github" style="font-size:24px"></i></a>
            </div>
        </div>
    </section>

    <footer>
        <div class="copyright">
            © 2024 | Created & Designed By <a href="#home">Group 8</a>
        </div>
        <div class="sm">
            <a href="#/"><i class="fa fa-facebook" style="font-size:24px"></i></a>
            <a href="#/"><i class="fa fa-instagram" style="font-size:24px"></i></a>
            <a href="#/"><i class="fa fa-linkedin" style="font-size:24px"></i></a>
            <a href="#"><i class="fa fa-telegram" style="font-size:24px"></i></a>
            <a href="#"><i class="fa fa-github" style="font-size:24px"></i></a>
        </div>
    </footer>
</body>
</html>