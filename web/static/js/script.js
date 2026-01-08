document.addEventListener('DOMContentLoaded', () => {
    const chatContainer = document.getElementById('chat-container');
    const userInput = document.getElementById('user-input');
    const sendBtn = document.getElementById('send-btn');
    const newChatBtn = document.getElementById('new-chat-btn');
    const modelSelect = document.getElementById('model-select');

    let currentController = null; // For invalidating/aborting previous requests if needed

    // Auto-resize textarea
    userInput.addEventListener('input', function() {
        this.style.height = 'auto'; // Reset height
        this.style.height = (this.scrollHeight) + 'px';
        
        // Enable/disable send button
        if (this.value.trim().length > 0) {
            sendBtn.removeAttribute('disabled');
        } else {
            sendBtn.setAttribute('disabled', 'true');
        }
    });

    // Handle Enter key (Shift+Enter for newline)
    userInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            if (!sendBtn.disabled) {
                sendMessage();
            }
        }
    });

    sendBtn.addEventListener('click', sendMessage);

    newChatBtn.addEventListener('click', () => {
        chatContainer.innerHTML = `
            <div class="message-wrapper">
                <div class="message">
                    <div class="avatar ai">AI</div>
                    <div class="message-content">Hello! How can I help you today?</div>
                </div>
            </div>
        `;
        userInput.focus();
    });

    // Load available models (optional: fetch from API)
    fetch('/v1/models')
        .then(res => res.json())
        .then(data => {
            if (data.data && Array.isArray(data.data) && data.data.length > 0) {
                modelSelect.innerHTML = ''; // Clear defaults
                data.data.forEach(model => {
                    const option = document.createElement('option');
                    option.value = model.id;
                    option.textContent = model.id;
                    modelSelect.appendChild(option);
                });
                // Set default preference if available in localStorage
                const savedModel = localStorage.getItem('selectedModel');
                if (savedModel && data.data.find(m => m.id === savedModel)) {
                    modelSelect.value = savedModel;
                }
            }
        })
        .catch(err => console.error('Failed to fetch models:', err));

    modelSelect.addEventListener('change', () => {
        localStorage.setItem('selectedModel', modelSelect.value);
    });

    async function sendMessage() {
        const text = userInput.value.trim();
        if (!text) return;

        // Clear input
        userInput.value = '';
        userInput.style.height = 'auto';
        sendBtn.setAttribute('disabled', 'true');

        // Add User Message
        addMessage(text, 'user');

        // Add AI Placeholder
        const aiMessageContentDiv = addMessage('', 'ai', true); // true = raw buffer for streaming

        const selectedModel = modelSelect.value || 'gemini-3-flash';

        try {
            currentController = new AbortController();
            
            const response = await fetch('/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: selectedModel,
                    messages: [
                        { role: 'user', content: text } 
                        // Note: In a real app we'd send history here
                    ],
                    stream: true
                }),
                signal: currentController.signal
            });

            if (!response.ok) {
                const errText = await response.text();
                aiMessageContentDiv.innerHTML = `<span style="color: #ff6b6b">Error: ${response.statusText} - ${errText}</span>`;
                return;
            }

            // Handle Stream
            const reader = response.body.getReader();
            const decoder = new TextDecoder('utf-8');
            let buffer = '';
            let fullText = '';

            while (true) {
                const { value, done } = await reader.read();
                if (done) break;

                const chunk = decoder.decode(value, { stream: true });
                buffer += chunk;

                const lines = buffer.split('\n');
                buffer = lines.pop(); // Keep incomplete line

                for (const line of lines) {
                    const trimmed = line.trim();
                    if (trimmed.startsWith('data: ')) {
                        const dataStr = trimmed.slice(6);
                        if (dataStr === '[DONE]') continue;

                        try {
                            const data = JSON.parse(dataStr);
                            const content = data.choices?.[0]?.delta?.content || '';
                            if (content) {
                                fullText += content;
                                // Basic Markdown update (re-rendering efficiently is harder, 
                                // but for valid markdown streams, marked handles incomplete blocks moderately well if careful, 
                                // or we just wait for chunks. For better UX, we just render fullText continuously.)
                                aiMessageContentDiv.innerHTML = marked.parse(fullText);
                                hljs.highlightAll(); // Re-highlight code blocks
                                scrollToBottom();
                            }
                        } catch (e) {
                            console.warn('Error parsing stream chunk:', e);
                        }
                    }
                }
            }

        } catch (error) {
            if (error.name !== 'AbortError') {
                 aiMessageContentDiv.innerHTML += `<br><span style="color: #ff6b6b">[Error: ${error.message}]</span>`;
            }
        } finally {
            currentController = null;
        }
    }

    function addMessage(text, sender, returnElement = false) {
        const wrapper = document.createElement('div');
        wrapper.className = 'message-wrapper';
        
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message';
        
        const avatar = document.createElement('div');
        avatar.className = `avatar ${sender}`;
        avatar.textContent = sender === 'user' ? 'U' : 'AI';
        
        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';
        
        if (sender === 'ai' && !text) {
             contentDiv.innerHTML = '<span class="cursor"></span>'; // Loading indicator
        } else {
             contentDiv.innerHTML = sender === 'ai' ? marked.parse(text) : escapeHtml(text).replace(/\n/g, '<br>');
        }

        messageDiv.appendChild(avatar);
        messageDiv.appendChild(contentDiv);
        wrapper.appendChild(messageDiv);
        chatContainer.appendChild(wrapper);

        scrollToBottom();

        if (sender === 'ai') {
             hljs.highlightAll();
        }

        if (returnElement) return contentDiv;
    }

    function scrollToBottom() {
        // Only scroll if near bottom or user hasn't scrolled up significantly? 
        // For now, always scroll to latest message
        window.scrollTo(0, document.body.scrollHeight);
        chatContainer.scrollTop = chatContainer.scrollHeight;
    }

    function escapeHtml(unsafe) {
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }
});
