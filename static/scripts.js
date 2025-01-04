document.addEventListener('DOMContentLoaded', function() {
    const toggler = document.getElementById('navbar-toggler');
    const menu = document.getElementById('navbar-menu');

    toggler.addEventListener('click', function() {
        menu.classList.toggle('show');
    });
});

document.addEventListener('DOMContentLoaded', function() {
    const chatButton = document.getElementById('chat-button');
    const chatPopup = document.getElementById('chat-popup');
    const closeChat = document.getElementById('close-chat');
    const sendButton = document.getElementById('send-button');
    const userInput = document.getElementById('user-input');
    const chatBox = document.getElementById('chat-box');

    chatButton.addEventListener('click', function() {
        chatPopup.style.display = 'block';
    });

    closeChat.addEventListener('click', function() {
        chatPopup.style.display = 'none';
    });

    sendButton.addEventListener('click', function() {
        sendMessage();
    });

    userInput.addEventListener('keypress', function(event) {
        if (event.key === 'Enter') {
            sendMessage();
        }
    });

    async function sendMessage() {
        const message = userInput.value.trim();
        if (message === '') return;

        // Display user message
        const userMessage = document.createElement('p');
        userMessage.textContent = `You: ${message}`;
        chatBox.appendChild(userMessage);
        chatBox.scrollTop = chatBox.scrollHeight;

        // Send message to backend
        const response = await fetch('/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ message: message })
        });
        const data = await response.json();

        // Display AI response
        const aiMessage = document.createElement('p');
        aiMessage.textContent = `AI: ${data.response}`;
        chatBox.appendChild(aiMessage);
        chatBox.scrollTop = chatBox.scrollHeight;

        // Clear input
        userInput.value = '';
    }
});