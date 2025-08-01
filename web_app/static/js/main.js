/**
 * FMC Tool - Main JavaScript
 * Handles common functionality across the application
 */

$(document).ready(function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Handle sidebar toggle for mobile
    $('#sidebarToggle').on('click', function() {
        $('.sidebar').toggleClass('active');
    });
    
    // Handle dropdown menus
    $('.dropdown-toggle').dropdown();
    
    // Handle refresh button animation
    $('#refreshBtn').on('click', function() {
        const $icon = $(this).find('i');
        $icon.addClass('fa-spin');
        
        // Remove spin class after animation completes
        setTimeout(function() {
            $icon.removeClass('fa-spin');
        }, 1000);
    });
    
    // Handle form submission prevention
    $('form').on('submit', function(e) {
        e.preventDefault();
        // Forms are handled via JavaScript, not traditional submission
    });
    
    // Add active class to current nav item based on URL
    const currentPath = window.location.pathname;
    $('.nav-link').each(function() {
        const $this = $(this);
        if ($this.attr('href') === currentPath) {
            $this.addClass('active');
        }
    });
});
