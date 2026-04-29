// Firebase Messaging Service Worker
importScripts('https://www.gstatic.com/firebasejs/9.22.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/9.22.0/firebase-messaging-compat.js');

// Initialize Firebase
firebase.initializeApp({
  apiKey: "AIzaSyAsU9o8fyhIh8JbOx7U4vhktH_lpVxv828",
  authDomain: "poraqui-notifications.firebaseapp.com",
  projectId: "poraqui-notifications",
  storageBucket: "poraqui-notifications.firebasestorage.app",
  messagingSenderId: "1005172593006",
  appId: "1:1005172593006:web:40206169f28002c155717f"
});

const messaging = firebase.messaging();

// Handle background messages
messaging.onBackgroundMessage((payload) => {
  console.log('Received background message ', payload);
  const notificationTitle = payload.notification.title;
  const notificationOptions = {
    body: payload.notification.body,
    icon: '/static/icons/icon-192x192.png'
  };

  self.registration.showNotification(notificationTitle, notificationOptions);
});