// static/chat.js
document.getElementById('send-btn').addEventListener('click', sendMessage);
document.getElementById('chat-input').addEventListener('keypress', function(event) {
    if (event.key === 'Enter') {
        sendMessage();
    }
});

function sendMessage() {
    var input = document.getElementById('chat-input');
    var message = input.value.trim();
    if (message) {
        displayMessage(message, 'user');
        input.value = '';
        // Simulate AI response (replace with actual AI call)
        setTimeout(function() {
            displayMessage("I'm here to help! What do you need assistance with?", 'ai');
        }, 1000);
    }
}

function selectOption(option) {
    displayMessage(`Selected option: ${option}`, 'user');
    setTimeout(function() {
        displayMessage(`You chose ${option}. Please provide more details or ask your question.`, 'ai');
    }, 1000);
}

function displayMessage(message, sender) {
    var chatMessages = document.getElementById('chat-messages');
    var messageElement = document.createElement('div');
    messageElement.classList.add('chat-message');
    if (sender === 'user') {
        messageElement.classList.add('user');
    } else {
        messageElement.classList.add('ai');
    }
    messageElement.innerHTML = message;
    chatMessages.appendChild(messageElement);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}