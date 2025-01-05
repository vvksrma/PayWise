document.addEventListener('DOMContentLoaded', function () {
    const toggler = document.querySelector('.navbar-toggler');
    const menu = document.querySelector('.navbar-menu');

    toggler.addEventListener('click', function () {
        menu.classList.toggle('show');
    });
});