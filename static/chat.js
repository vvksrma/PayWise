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

        // Add loading animation
        var loadingAnimation = document.createElement('div');
        loadingAnimation.classList.add('loading');
        loadingAnimation.innerHTML = '<span></span><span></span><span></span>';
        var chatMessages = document.getElementById('chat-messages');
        chatMessages.appendChild(loadingAnimation);
        chatMessages.scrollTop = chatMessages.scrollHeight;

        // Send the message to the backend to get an AI response
        fetch('/get_response', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ message: message })
        })
        .then(response => response.json())
        .then(data => {
            // Remove loading animation
            chatMessages.removeChild(loadingAnimation);
            displayMessage(data.response, 'ai');
        })
        .catch(error => {
            console.error('Error:', error);
            chatMessages.removeChild(loadingAnimation);
            displayMessage("Sorry, I couldn't process your request. Please try again later.", 'ai');
        });
    }
}

function displayMessage(message, sender) {
    var chatMessages = document.getElementById('chat-messages');
    var messageElement = document.createElement('div');
    messageElement.classList.add('chat-message');
    messageElement.classList.add(sender);

    var messageContent = document.createElement('p');
    messageContent.innerHTML = formatMessage(message);
    messageElement.appendChild(messageContent);

    chatMessages.appendChild(messageElement);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function formatMessage(message) {
    // Replace **text** with <strong>text</strong>
    return message.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>').replace(/\n/g, '<br>');
}