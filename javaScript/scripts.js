$(document).ready(function(){
    // Sticky navbar on scroll
    $(window).scroll(function(){
        if(this.scrollY > 20){
            $(".navbar").addClass("sticky");
        } else {
            $(".navbar").removeClass("sticky");
        }
    });

    // Mobile menu toggler
    $('.menu-toggler').click(function(){
        $(this).toggleClass("active");
        $(".navbar-menu").toggleClass("active");
    });
});


