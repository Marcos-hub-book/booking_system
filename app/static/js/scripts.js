// This file contains JavaScript for client-side interactivity, such as form validation and dynamic updates to the schedule.

document.addEventListener('DOMContentLoaded', function() {
    const scheduleForm = document.getElementById('schedule-form');
    const serviceSelect = document.getElementById('service-select');
    const professionalSelect = document.getElementById('professional-select');
    const appointmentDate = document.getElementById('appointment-date');
    const appointmentTime = document.getElementById('appointment-time');

    // Function to validate form inputs
    function validateForm() {
        let isValid = true;
        if (!serviceSelect.value) {
            isValid = false;
            alert('Please select a service.');
        }
        if (!professionalSelect.value) {
            isValid = false;
            alert('Please select a professional.');
        }
        if (!appointmentDate.value) {
            isValid = false;
            alert('Please select a date.');
        }
        if (!appointmentTime.value) {
            isValid = false;
            alert('Please select a time.');
        }
        return isValid;
    }

    // Event listener for form submission
    if (scheduleForm) {
        scheduleForm.addEventListener('submit', function(event) {
            if (!validateForm()) {
                event.preventDefault();
            }
        });
    }

    // Example function to dynamically update available times based on selected service and professional
    function updateAvailableTimes() {
        // Fetch available times from the server based on selected service and professional
        // This is a placeholder for the actual implementation
        console.log('Fetching available times...');
    }

    // Event listeners for changes in service and professional selections
    if (serviceSelect) serviceSelect.addEventListener('change', updateAvailableTimes);
    if (professionalSelect) professionalSelect.addEventListener('change', updateAvailableTimes);

    // PWA service worker registration
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', function() {
            navigator.serviceWorker.register('/sw.js')
                .then(function(reg) {
                    console.log('Service Worker registrado com sucesso:', reg);
                })
                .catch(function(err) {
                    console.warn('Falha ao registrar Service Worker:', err);
                });
        });
    }
});