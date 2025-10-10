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
    scheduleForm.addEventListener('submit', function(event) {
        if (!validateForm()) {
            event.preventDefault();
        }
    });

    // Example function to dynamically update available times based on selected service and professional
    function updateAvailableTimes() {
        // Fetch available times from the server based on selected service and professional
        // This is a placeholder for the actual implementation
        console.log('Fetching available times...');
    }

    // Event listeners for changes in service and professional selections
    serviceSelect.addEventListener('change', updateAvailableTimes);
    professionalSelect.addEventListener('change', updateAvailableTimes);
});