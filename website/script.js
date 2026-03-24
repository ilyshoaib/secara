document.addEventListener('DOMContentLoaded', () => {
    const copyBtn = document.getElementById('copy-btn');
    const command = 'pip install -e .';

    copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(command).then(() => {
            const originalText = copyBtn.innerText;
            copyBtn.innerText = 'Copied!';
            copyBtn.style.color = '#10b981';
            setTimeout(() => {
                copyBtn.innerText = originalText;
                copyBtn.style.color = '';
            }, 2000);
        });
    });

    // Mock terminal animation
    const terminal = document.getElementById('terminal-content');
    const lines = terminal.querySelectorAll('span');
    
    // Hide all lines initially
    lines.forEach(l => l.style.opacity = '0');

    let delay = 500;
    lines.forEach((line, index) => {
        setTimeout(() => {
            line.style.opacity = '1';
            line.style.transition = 'opacity 0.5s ease-in-out';
        }, delay);
        delay += (index === 0) ? 1000 : 600;
    });
});
