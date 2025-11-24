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
    
    // Handle dropdown menus using Bootstrap 5
    var dropdownElementList = [].slice.call(document.querySelectorAll('.dropdown-toggle'));
    var dropdownList = dropdownElementList.map(function (dropdownToggleEl) {
        return new bootstrap.Dropdown(dropdownToggleEl);
    });
    
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
    
    // Enhanced collapsible handling with smooth animations
    $('.stat-header').on('click', function() {
        const $details = $(this).siblings('.stat-details');
        const $expand = $(this).find('.stat-expand');
        
        if ($details.hasClass('collapsed')) {
            $details.removeClass('collapsed');
            $expand.css('transform', 'rotate(0deg)');
        } else {
            $details.addClass('collapsed');
            $expand.css('transform', 'rotate(-90deg)');
        }
    });
    
    // Smooth dropdown toggle handler
    $('.dropdown-toggle, [id*="button"][id*="dropdown"]').on('click', function(e) {
        const targetId = $(this).attr('id');
        if (targetId && targetId.includes('button')) {
            const dropdownId = targetId.replace('button', 'dropdown').replace('-button', '-dropdown');
            const $dropdown = $('#' + dropdownId);
            if ($dropdown.length) {
                $dropdown.toggleClass('hidden');
                // Add animation class
                if (!$dropdown.hasClass('hidden')) {
                    $dropdown.addClass('dropdown-content');
                }
            }
        }
    });
});

/**
 * Smooth toggle function with animation support
 * @param {string} elementId - ID of the element to toggle
 * @param {number} duration - Animation duration in ms (default 350)
 */
function smoothToggle(elementId, duration = 350) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    if (element.classList.contains('hidden')) {
        element.classList.remove('hidden');
        element.style.display = 'block';
        // Trigger reflow
        element.offsetHeight;
        element.classList.add('fade-in');
    } else {
        element.style.opacity = '0';
        setTimeout(() => {
            element.classList.add('hidden');
            element.style.opacity = '1';
            element.classList.remove('fade-in');
        }, duration);
    }
}

/**
 * Smooth slide toggle for collapsible elements
 * @param {string} elementId - ID of the element to slide
 */
function smoothSlideToggle(elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    if (element.classList.contains('hidden')) {
        element.classList.remove('hidden');
        element.classList.add('collapsible-content');
        element.style.maxHeight = element.scrollHeight + 'px';
    } else {
        element.style.maxHeight = '0';
        setTimeout(() => {
            element.classList.add('hidden');
        }, 300);
    }
}

/**
 * Add fade-in animation to dynamically created elements
 * @param {HTMLElement} element - The element to animate
 */
function addFadeInAnimation(element) {
    if (element) {
        element.classList.add('fade-in');
        setTimeout(() => {
            element.classList.remove('fade-in');
        }, 300);
    }
}
