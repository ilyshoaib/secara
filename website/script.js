document.addEventListener('DOMContentLoaded', () => {
    const copyBtn = document.getElementById('copy-btn');
    const command = 'pip install -e .';

    copyBtn.addEventListener('click', () => {
        const textToCopy = command;
        
        const performCopy = () => {
            const originalText = copyBtn.innerText;
            copyBtn.innerText = 'Copied!';
            copyBtn.style.color = '#10b981';
            setTimeout(() => {
                copyBtn.innerText = originalText;
                copyBtn.style.color = '';
            }, 2000);
        };

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(textToCopy).then(performCopy);
        } else {
            // Fallback for non-secure contexts
            const textArea = document.createElement("textarea");
            textArea.value = textToCopy;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                performCopy();
            } catch (err) {
                console.error('Fallback copy failed', err);
            }
            document.body.removeChild(textArea);
        }
    });

    // Mock terminal animation
    const terminal = document.getElementById('terminal-content');
    const lines = terminal.querySelectorAll('span');
    
    let delay = 800;
    lines.forEach((line, index) => {
        setTimeout(() => {
            line.classList.add('visible');
        }, delay);
        delay += (index === 0) ? 1200 : 700;
    });
});
