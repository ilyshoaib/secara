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
    
    let delay = 800;
    lines.forEach((line, index) => {
        setTimeout(() => {
            line.classList.add('visible');
        }, delay);
        delay += (index === 0) ? 1200 : 700;
    });
});
