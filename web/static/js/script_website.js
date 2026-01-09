document.addEventListener('DOMContentLoaded', () => {
    const chatContainer = document.getElementById('chat-container');
    const userInput = document.getElementById('user-input');
    const sendBtn = document.getElementById('send-btn');
    const newChatBtn = document.getElementById('new-chat-btn');
    const modelSelect = document.getElementById('model-select');

    // Login View Elements
    const loginView = document.getElementById('login-view');
    const retryBtn = document.getElementById('retry-btn');
    const loginBtn = document.getElementById('login-btn');
    const loginStatus = document.getElementById('login-status');
    const modelSelectorContainer = document.getElementById('model-selector-container');
    const inputContainer = document.querySelector('.input-container');
    const stopBtn = document.getElementById('stop-btn');
    const menuToggle = document.getElementById('menu-toggle');
    const sidebar = document.querySelector('.sidebar');
    const sidebarOverlay = document.getElementById('sidebar-overlay');

    if (menuToggle) {
        menuToggle.addEventListener('click', () => {
            sidebar.classList.add('open');
            sidebarOverlay.classList.add('visible');
        });
    }

    if (sidebarOverlay) {
        sidebarOverlay.addEventListener('click', () => {
            sidebar.classList.remove('open');
            sidebarOverlay.classList.remove('visible');
        });
    }

    // Close sidebar on item click (mobile)
    const historyItems = document.querySelectorAll('.history-item');
    historyItems.forEach(item => {
        item.addEventListener('click', () => {
            if (window.innerWidth <= 768) {
                sidebar.classList.remove('open');
                sidebarOverlay.classList.remove('visible');
            }
        });
    });

    let currentController = null;
    let editingWrapper = null;

    stopBtn.addEventListener('click', () => {
        if (currentController) {
            currentController.abort();
            currentController = null;
            stopBtn.classList.remove('visible');
            sendBtn.style.display = 'flex';

            // Update the last AI message to show "Stopped"
            const messages = chatContainer.querySelectorAll('.message-content');
            if (messages.length > 0) {
                const lastMessage = messages[messages.length - 1];
                if (lastMessage.innerHTML.includes('Thinking...')) {
                    lastMessage.innerHTML = '<span style="color: #ff6b6b">⏸️ Stopped</span>';
                }
            }
        }
    });

    function showLogin() {
        if (loginView) loginView.style.display = 'flex';
        if (chatContainer) chatContainer.style.display = 'none';
        if (modelSelectorContainer) modelSelectorContainer.style.display = 'none';
        if (inputContainer) inputContainer.style.display = 'none';
        if (modelSelect) {
            modelSelect.innerHTML = '<option value="" disabled selected>Login Required</option>';
        }

        // Hide UI elements that shouldn't be visible when not authenticated
        const mobileHeader = document.querySelector('.mobile-header');
        const sidebar = document.querySelector('.sidebar');
        const mainContent = document.querySelector('.main-content');
        if (mobileHeader) mobileHeader.style.display = 'none';
        if (sidebar) sidebar.style.display = 'none';
        if (mainContent) {
            mainContent.style.display = 'flex'; // Need main content visible because login is inside it
        }
    }

    function showChat() {
        if (loginView) loginView.style.display = 'none';
        if (chatContainer) chatContainer.style.display = 'flex';
        if (modelSelectorContainer) modelSelectorContainer.style.display = 'flex';
        if (inputContainer) inputContainer.style.display = 'flex';

        const mobileHeader = document.querySelector('.mobile-header');
        const sidebar = document.querySelector('.sidebar');
        const mainContent = document.querySelector('.main-content');

        if (sidebar) sidebar.style.display = 'flex';
        if (mainContent) mainContent.style.display = 'flex';

        // Mobile header logic
        if (mobileHeader && window.innerWidth <= 768) {
            mobileHeader.style.display = 'flex';
        }
    }

    if (retryBtn) {
        retryBtn.addEventListener('click', () => {
            location.reload();
        });
    }

    if (loginBtn) {
        loginBtn.addEventListener('click', async () => {
            loginStatus.style.color = 'var(--text-secondary)';
            loginStatus.textContent = 'Opening login page... Check your browser details/popups.';
            loginBtn.disabled = true;

            try {
                const res = await fetch('/api/antigravity_login', { method: 'POST' });
                if (!res.ok) {
                    const errText = await res.text();
                    throw new Error(errText || 'Login request failed');
                }
                const data = await res.json();

                if (data.url) {
                    // Open the login URL in a new tab
                    window.open(data.url, '_blank');

                    loginStatus.style.color = 'var(--accent-color)';
                    loginStatus.textContent = 'Login page opened. Waiting for completion...';

                    // Poll for login success by checking if models endpoint returns valid data
                    // (If logged in, it returns 200 and list; if not, it returns pending or error)
                    const pollInterval = setInterval(async () => {
                        try {
                            const modelRes = await fetch(`${API_BASE}/v1/models`);
                            if (modelRes.ok) {
                                const modelData = await modelRes.json();
                                if (modelData.data && modelData.data.length > 0) {
                                    clearInterval(pollInterval);
                                    loginStatus.style.color = '#4ade80'; // Green
                                    loginStatus.textContent = 'Login successful! Reloading...';
                                    setTimeout(() => location.reload(), 1000);
                                }
                            }
                        } catch (e) {
                            // Ignore errors during polling
                        }
                    }, 2000);

                    // Optional: Stop polling after 5 minutes
                    setTimeout(() => {
                        clearInterval(pollInterval);
                        if (loginStatus.textContent.includes('Waiting')) {
                            loginStatus.style.color = '#ff6b6b';
                            loginStatus.textContent = 'Login timed out. Please try again.';
                            loginBtn.disabled = false;
                        }
                    }, 300000);

                } else if (data.status === 'success') {
                    // Should not happen now but kept for legacy
                    loginStatus.style.color = '#4ade80';
                    loginStatus.textContent = 'Login successful! Reloading...';
                    setTimeout(() => location.reload(), 1000);
                } else {
                    throw new Error('Unknown login response');
                }
            } catch (err) {
                console.error(err);
                loginStatus.style.color = '#ff6b6b';
                loginStatus.textContent = 'Login Error: ' + err.message;
                loginBtn.disabled = false;
            }
        });
    }

    // Dynamic API endpoint - uses same hostname as WebUI but port 8045
    // This allows access from mobile devices on the same network
    const API_BASE = `${window.location.protocol}//${window.location.hostname}:8045`;

    userInput.addEventListener('input', function () {
        this.style.height = 'auto'; // Reset height
        this.style.height = (this.scrollHeight) + 'px';
        if (this.value.trim().length > 0) {
            sendBtn.removeAttribute('disabled');
        } else {
            sendBtn.setAttribute('disabled', 'true');
        }
    });

    userInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            if (!sendBtn.disabled) {
                sendMessage();
            }
        }
    });

    sendBtn.addEventListener('click', sendMessage);

    // Message queue system
    let messageQueue = [];
    let isProcessing = false;

    async function processQueue() {
        if (isProcessing || messageQueue.length === 0) return;

        isProcessing = true;
        userInput.disabled = true;
        sendBtn.disabled = true;

        while (messageQueue.length > 0) {
            const item = messageQueue.shift();
            await sendMessageInternal(item.text, item.targetWrapper);
        }

        isProcessing = false;
        userInput.disabled = false;
        if (userInput.value.trim().length > 0) {
            sendBtn.disabled = false;
        }
    }

    function sendMessage() {
        const text = userInput.value.trim();
        if (!text) return;

        messageQueue.push({ text, targetWrapper: editingWrapper });
        editingWrapper = null;

        userInput.value = '';
        userInput.style.height = 'auto';

        processQueue();
    }

    newChatBtn.addEventListener('click', () => {
        editingWrapper = null;
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

    // Load models
    fetch(`${API_BASE}/v1/models`)
        .then(async res => {
            if (!res.ok) {
                const errText = await res.text();
                if (errText.includes('no accounts available') || res.status === 401 || res.status === 403) {
                    showLogin();
                    throw new Error('Authentication Required');
                }
            }
            return res.json();
        })
        .then(data => {
            console.log('Models Fetch Result:', data);

            if (!data || data.error || !data.data || !Array.isArray(data.data) || data.data.length === 0) {
                console.warn('Authentication or No-Accounts detected. Triggering Login View.');
                showLogin();
                return;
            }

            console.log('Authentication Successful. Loading models into UI.');
            modelSelect.innerHTML = '';
            showChat();

            // Load exhausted models from localStorage
            const exhaustedModels = JSON.parse(localStorage.getItem('exhaustedModels') || '[]');

            data.data.forEach(model => {
                // Filter out models starting with 'chat_'
                if (model.id.startsWith('chat_')) return;

                const option = document.createElement('option');
                option.value = model.id;

                if (exhaustedModels.includes(model.id)) {
                    option.textContent = model.id + ' ⚠️';
                    option.style.color = '#ff6b6b';
                } else {
                    option.textContent = model.id;
                }

                modelSelect.appendChild(option);
            });

            const savedModel = localStorage.getItem('selectedModel');
            if (savedModel && data.data.find(m => m.id === savedModel) && !savedModel.startsWith('chat_')) {
                modelSelect.value = savedModel;
            } else if (data.data.find(m => m.id === 'gemini-3-pro-image')) {
                modelSelect.value = 'gemini-3-pro-image';
                localStorage.setItem('selectedModel', 'gemini-3-pro-image');
            }
        })
        .catch(err => {
            console.error('Failed to fetch models:', err);
            showLogin();
        });

    modelSelect.addEventListener('change', () => {
        localStorage.setItem('selectedModel', modelSelect.value);
    });

    async function sendMessageInternal(text, targetWrapper = null) {
        let aiMessageContentDiv;

        if (targetWrapper) {
            // Versioning: Remove all subsequent messages from current branch
            const versions = targetWrapper._versions;
            const currentV = versions[targetWrapper._activeVersion];

            // Save current branch
            currentV.nodes = [];
            let next = targetWrapper.nextElementSibling;
            while (next) {
                const toRemove = next;
                next = next.nextElementSibling;
                currentV.nodes.push(toRemove);
                toRemove.remove();
            }

            // Create new version
            const newV = {
                text: text,
                nodes: []
            };
            versions.push(newV);
            targetWrapper._activeVersion = versions.length - 1;

            // Update UI for the user message
            targetWrapper.querySelector('.message-content').innerHTML = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;").replace(/\n/g, '<br>');
            updateVersionUI(targetWrapper);

            // Add placeholder for new AI response
            aiMessageContentDiv = addMessage('<span class="thinking-indicator">Thinking...</span>', 'ai', true);
        } else {
            addMessage(text, 'user');
            // Initial placeholder with Thinking indicator
            aiMessageContentDiv = addMessage('<span class="thinking-indicator">Thinking...</span>', 'ai', true);
        }

        // Update Title
        const originalTitle = document.title;
        document.title = "Thinking... | Antigravity";

        const selectedModel = modelSelect.value || 'gemini-3-pro-image';

        let isThinking = true;
        let fullContent = '';
        let fullReasoning = '';

        try {
            currentController = new AbortController();

            // Show stop button, hide send button
            stopBtn.classList.add('visible');
            sendBtn.style.display = 'none';

            const response = await fetch(`${API_BASE}/v1/chat/completions`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include', // Send cookies with request
                body: JSON.stringify({
                    model: selectedModel,
                    messages: [
                        { role: 'user', content: text }
                    ],
                    stream: true
                }),
                signal: currentController.signal
            });

            document.title = originalTitle;

            if (!response.ok) {
                const errText = await response.text();
                if (errText.includes('no accounts available')) {
                    showLogin();
                    aiMessageContentDiv.parentElement.parentElement.remove();
                    return;
                }

                let displayError = errText;
                try {
                    const jsonError = JSON.parse(errText);
                    if (jsonError.error) {
                        const rawError = jsonError.error;
                        if (typeof rawError === 'string') {
                            // 1. Try to extract nested Upstream JSON error first (most accurate)
                            // Matches "returned <status>: <json>"
                            const match = rawError.match(/returned \d+: ({[\s\S]*})/);
                            let nestedParsed = false;

                            if (match && match[1]) {
                                try {
                                    const nested = JSON.parse(match[1]);
                                    if (nested.error && nested.error.message) {
                                        displayError = `**${nested.error.status || 'Error'}**: ${nested.error.message}`;
                                        if (nested.error.details) {
                                            // Optionally add details if available
                                        }
                                        nestedParsed = true;
                                    }
                                } catch (e) {
                                    // Extract failed, proceed to fallbacks 
                                }
                            }

                            if (!nestedParsed) {
                                // 2. Check for Quota/Rate Limit (Common 429) via string matching
                                if (rawError.toLowerCase().includes('resource has been exhausted') || rawError.includes('429')) {
                                    displayError = "⚠️ **Quota Exceeded (429)**\n\nThe AI provider returned 'Resource Exhausted'. Please try again later or switch models.";

                                    // Mark the model in the dropdown and save to localStorage
                                    const exhaustedModels = JSON.parse(localStorage.getItem('exhaustedModels') || '[]');
                                    if (!exhaustedModels.includes(selectedModel)) {
                                        exhaustedModels.push(selectedModel);
                                        localStorage.setItem('exhaustedModels', JSON.stringify(exhaustedModels));
                                    }

                                    const options = modelSelect.options;
                                    for (let i = 0; i < options.length; i++) {
                                        if (options[i].value === selectedModel) {
                                            // Add ⚠️ if not already present
                                            if (!options[i].textContent.includes('⚠️')) {
                                                options[i].textContent += ' ⚠️';
                                                options[i].style.color = '#ff6b6b';
                                            }
                                        }
                                    }
                                }
                                // 3. Check for NOT_FOUND errors
                                else if (rawError.toLowerCase().includes('not found') || rawError.includes('404') || rawError.includes('NOT_FOUND')) {
                                    displayError = "⚠️ **Model Not Found**\n\nThis model is not available or does not exist. Please try a different model.";

                                    // Mark the model in the dropdown and save to localStorage
                                    const exhaustedModels = JSON.parse(localStorage.getItem('exhaustedModels') || '[]');
                                    if (!exhaustedModels.includes(selectedModel)) {
                                        exhaustedModels.push(selectedModel);
                                        localStorage.setItem('exhaustedModels', JSON.stringify(exhaustedModels));
                                    }

                                    const options = modelSelect.options;
                                    for (let i = 0; i < options.length; i++) {
                                        if (options[i].value === selectedModel) {
                                            if (!options[i].textContent.includes('⚠️')) {
                                                options[i].textContent += ' ⚠️';
                                                options[i].style.color = '#ff6b6b';
                                            }
                                        }
                                    }
                                }
                                else {
                                    // 4. Fallback to raw error
                                    displayError = rawError;
                                }
                            }
                        } else if (rawError.message) {
                            displayError = rawError.message;
                        }
                    }
                } catch (e) {
                    console.warn('Failed to parse error JSON:', e);
                }

                // Use marked to render the error message so we can use bolding/formatting
                const formattedError = marked.parse(displayError);

                aiMessageContentDiv.innerHTML = `
                            <div style="border: 1px solid #ff6b6b; background: rgba(255,107,107,0.1); padding: 15px; border-radius: 8px;">
                                <div style="color: #ff6b6b; font-weight: bold; margin-bottom: 8px; display: flex; align-items: center; gap: 6px;">
                                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                                    Request Failed (${response.status})
                                </div>
                                <div style="color: #ff9e9e; font-size: 0.95em; line-height: 1.5;" class="error-content">${formattedError}</div>
                            </div>`;
                return;
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder('utf-8');
            let buffer = '';

            while (true) {
                const { value, done } = await reader.read();
                if (done) break;

                const chunk = decoder.decode(value, { stream: true });
                buffer += chunk;

                const lines = buffer.split('\n');
                buffer = lines.pop();

                for (const line of lines) {
                    const trimmed = line.trim();
                    if (trimmed.startsWith('data: ')) {
                        const dataStr = trimmed.slice(6);
                        if (dataStr === '[DONE]') continue;

                        try {
                            const data = JSON.parse(dataStr);
                            let chunkContent = data.choices?.[0]?.delta?.content || '';
                            let chunkReasoning = data.choices?.[0]?.delta?.reasoning_content || '';

                            // Handle <think> tags in content
                            // Simple check: if content has <think>, move it to reasoning
                            if (chunkContent.includes('<think>')) {
                                // This is a naive split for streaming, but works if tags are not split across chunks usually
                                // Better: Accumulate content, then regex extract.
                            }

                            fullContent += chunkContent;
                            fullReasoning += chunkReasoning;

                            // Post-processing to move <think> blocks from content to reasoning
                            // This regex extracts <think>...</think> content. 
                            // Note: It might flicker if the tag is incomplete, but eventual consistency works.
                            const thinkMatch = fullContent.match(/<think>([\s\S]*?)(?:<\/think>|$)/);
                            if (thinkMatch) {
                                fullReasoning += thinkMatch[1];
                                fullContent = fullContent.replace(thinkMatch[0], ''); // Remove from content
                            }

                            if (fullContent || fullReasoning) {
                                if (isThinking) {
                                    isThinking = false;
                                    aiMessageContentDiv.innerHTML = '';
                                }

                                // Capture current open state if existing
                                const existingDetails = aiMessageContentDiv.querySelector('.reasoning-details');
                                const isOpen = existingDetails ? existingDetails.hasAttribute('open') : false;

                                let finalHtml = '';

                                // Render Reasoning Block
                                if (fullReasoning.trim()) {
                                    let rText = fullReasoning;
                                    let rHtml = marked.parse(rText);
                                    // Re-apply open attribute if it was open
                                    const openAttr = isOpen ? 'open' : '';
                                    finalHtml += `
                                                <details class="reasoning-container reasoning-details" ${openAttr}>
                                                    <summary class="reasoning-summary">
                                                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                            <path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm1 15h-2v-2h2zm0-4h-2V7h2z"/>
                                                        </svg>
                                                        Thought Process
                                                    </summary>
                                                    <div class="reasoning-content">
                                                        ${rHtml}
                                                        <button class="reasoning-hide-btn" onclick="this.closest('details').removeAttribute('open')">
                                                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                                <polyline points="18 15 12 9 6 15"></polyline>
                                                            </svg>
                                                            Hide
                                                        </button>
                                                    </div>
                                                </details>`;
                                }

                                // Render Main Content
                                if (fullContent) {
                                    finalHtml += marked.parse(fullContent);
                                } else if (fullReasoning && !fullContent) {
                                    // If only reasoning so far, show thinking indicator below it
                                    finalHtml += '<div class="thinking-indicator">Thinking...</div>';
                                }

                                aiMessageContentDiv.innerHTML = finalHtml;
                                hljs.highlightAll();
                                enhanceCodeBlocks(aiMessageContentDiv);

                                // Render mathematical formulas with KaTeX
                                if (typeof renderMathInElement !== 'undefined') {
                                    renderMathInElement(aiMessageContentDiv, {
                                        delimiters: [
                                            { left: '$$', right: '$$', display: true },
                                            { left: '$', right: '$', display: false },
                                            { left: '\\[', right: '\\]', display: true },
                                            { left: '\\(', right: '\\)', display: false }
                                        ],
                                        throwOnError: false
                                    });
                                }

                                scrollToBottom();
                            }
                        } catch (e) {
                            console.warn('Error parsing stream chunk:', e);
                        }
                    }
                }
            }

        } catch (error) {
            document.title = originalTitle;
            if (error.name !== 'AbortError') {
                aiMessageContentDiv.innerHTML += `<br><span style="color: #ff6b6b">[Error: ${error.message}]</span>`;
            }
        } finally {
            currentController = null;
            stopBtn.classList.remove('visible');
            sendBtn.style.display = 'flex';
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
            // Empty AI message triggers parsing/logic later
        } else if (sender === 'ai' && text.includes('thinking-indicator')) {
            contentDiv.innerHTML = text; // Allow HTML for thinking indicator
        } else {
            contentDiv.innerHTML = sender === 'ai' ? marked.parse(text) : text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;").replace(/\n/g, '<br>');
        }

        messageDiv.appendChild(avatar);
        messageDiv.appendChild(contentDiv);

        // Add message actions (Edit/Copy)
        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'message-actions';

        // Edit button for user messages
        if (sender === 'user') {
            const editBtn = document.createElement('button');
            editBtn.className = 'message-btn';
            editBtn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                    <path d="M18.5 2.5a2.121 2.121 0 1 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                </svg>
                Edit
            `;
            editBtn.onclick = () => {
                userInput.value = text;
                userInput.focus();
                // Trigger input event to resize textarea
                const event = new Event('input', { bubbles: true });
                userInput.dispatchEvent(event);

                editingWrapper = wrapper;
                // Optional: Scroll to input
                inputContainer.scrollIntoView({ behavior: 'smooth' });
            };
            actionsDiv.appendChild(editBtn);
        }

        // Copy button
        const copyBtn = document.createElement('button');
        copyBtn.className = 'message-btn';
        copyBtn.innerHTML = `
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                    </svg>
                    Copy
                `;
        copyBtn.onclick = () => {
            const textToCopy = sender === 'ai' ? contentDiv.innerText || contentDiv.textContent : text;
            navigator.clipboard.writeText(textToCopy).then(() => {
                copyBtn.innerHTML = `
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="20 6 9 17 4 12"></polyline>
                            </svg>
                            Copied!
                        `;
                setTimeout(() => {
                    copyBtn.innerHTML = `
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                </svg>
                                Copy
                            `;
                }, 2000);
            });
        };

        actionsDiv.appendChild(copyBtn);
        wrapper.appendChild(messageDiv);
        wrapper.appendChild(actionsDiv);

        // Versioning initialization for user messages
        if (sender === 'user') {
            wrapper._versions = [{ text: text, nodes: [] }];
            wrapper._activeVersion = 0;

            const versionNav = document.createElement('div');
            versionNav.className = 'version-nav';
            versionNav.style.display = 'none'; // Hidden by default
            versionNav.innerHTML = `
                <button class="version-btn prev-btn" title="Previous version">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="15 18 9 12 15 6"></polyline>
                    </svg>
                </button>
                <span class="version-counter">1/1</span>
                <button class="version-btn next-btn" title="Next version">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="9 18 15 12 9 6"></polyline>
                    </svg>
                </button>
            `;

            versionNav.querySelector('.prev-btn').onclick = () => switchVersion(wrapper, -1);
            versionNav.querySelector('.next-btn').onclick = () => switchVersion(wrapper, 1);

            wrapper.appendChild(versionNav);
        }

        chatContainer.appendChild(wrapper);

        scrollToBottom();

        if (sender === 'ai') {
            hljs.highlightAll();

            // Render mathematical formulas
            if (typeof renderMathInElement !== 'undefined') {
                renderMathInElement(contentDiv, {
                    delimiters: [
                        { left: '$$', right: '$$', display: true },
                        { left: '$', right: '$', display: false },
                        { left: '\\[', right: '\\]', display: true },
                        { left: '\\(', right: '\\)', display: false }
                    ],
                    throwOnError: false
                });
            }
        }

        if (returnElement) return contentDiv;
    }

    function updateVersionUI(wrapper) {
        const nav = wrapper.querySelector('.version-nav');
        if (!nav) return;

        const count = wrapper._versions.length;
        if (count > 1) {
            nav.style.display = 'flex';
            nav.querySelector('.version-counter').textContent = `${wrapper._activeVersion + 1}/${count}`;
            nav.querySelector('.prev-btn').disabled = wrapper._activeVersion === 0;
            nav.querySelector('.next-btn').disabled = wrapper._activeVersion === count - 1;
        } else {
            nav.style.display = 'none';
        }
    }

    function switchVersion(wrapper, delta) {
        const versions = wrapper._versions;
        const oldV = versions[wrapper._activeVersion];

        // Save current branch
        oldV.nodes = [];
        let next = wrapper.nextElementSibling;
        while (next) {
            const toRemove = next;
            next = next.nextElementSibling;
            oldV.nodes.push(toRemove);
            toRemove.remove();
        }

        // Switch
        wrapper._activeVersion += delta;
        const newV = versions[wrapper._activeVersion];

        // Restore branch
        newV.nodes.forEach(node => chatContainer.appendChild(node));

        // Update UI
        wrapper.querySelector('.message-content').innerHTML = newV.text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;").replace(/\n/g, '<br>');
        updateVersionUI(wrapper);
        scrollToBottom();
    }

    function enhanceCodeBlocks(container) {
        const preBlocks = container.querySelectorAll('pre:not(.enhanced)');
        preBlocks.forEach(pre => {
            pre.classList.add('enhanced');

            // Detect language from code class
            const codeEl = pre.querySelector('code');
            let language = 'text';
            if (codeEl) {
                const classList = Array.from(codeEl.classList);
                const langClass = classList.find(cls => cls.startsWith('language-'));
                if (langClass) {
                    language = langClass.replace('language-', '');
                }
            }

            // Get code content
            const codeContent = pre.textContent;

            // Create wrapper
            const wrapper = document.createElement('div');
            wrapper.className = 'code-block-wrapper';

            // Create header
            const header = document.createElement('div');
            header.className = 'code-block-header';

            // Language label
            const langLabel = document.createElement('span');
            langLabel.className = 'code-language';
            langLabel.textContent = language;

            // Actions container
            const actions = document.createElement('div');
            actions.className = 'code-actions';

            // Copy button
            const copyBtn = document.createElement('button');
            copyBtn.className = 'code-action-btn';
            copyBtn.innerHTML = `
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                        </svg>
                        Copy
                    `;
            copyBtn.onclick = () => {
                navigator.clipboard.writeText(codeContent).then(() => {
                    copyBtn.innerHTML = `
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <polyline points="20 6 9 17 4 12"></polyline>
                                </svg>
                                Copied!
                            `;
                    setTimeout(() => {
                        copyBtn.innerHTML = `
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                    </svg>
                                    Copy
                                `;
                    }, 2000);
                });
            };

            // Download button
            const downloadBtn = document.createElement('button');
            downloadBtn.className = 'code-action-btn';
            downloadBtn.innerHTML = `
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="7 10 12 15 17 10"></polyline>
                            <line x1="12" y1="15" x2="12" y2="3"></line>
                        </svg>
                        Download
                    `;
            downloadBtn.onclick = () => {
                const blob = new Blob([codeContent], { type: 'text/plain' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `code.${language === 'text' ? 'txt' : language}`;
                a.click();
                URL.revokeObjectURL(url);
            };

            actions.appendChild(copyBtn);
            actions.appendChild(downloadBtn);

            header.appendChild(langLabel);
            header.appendChild(actions);

            // Wrap the pre element
            pre.parentNode.insertBefore(wrapper, pre);
            wrapper.appendChild(header);
            wrapper.appendChild(pre);
        });
    }

    function scrollToBottom() {
        window.scrollTo(0, document.body.scrollHeight);
        chatContainer.scrollTop = chatContainer.scrollHeight;
    }
});
