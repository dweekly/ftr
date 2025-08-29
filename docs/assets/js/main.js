// Copy to clipboard functionality
document.addEventListener('DOMContentLoaded', function() {
    // Copy button functionality
    const copyButtons = document.querySelectorAll('.copy-btn');
    
    copyButtons.forEach(button => {
        button.addEventListener('click', async (e) => {
            e.preventDefault();
            
            const textToCopy = button.getAttribute('data-copy');
            
            try {
                await navigator.clipboard.writeText(textToCopy);
                
                // Visual feedback
                const originalText = button.textContent;
                button.textContent = 'Copied!';
                button.style.background = 'var(--accent-primary)';
                
                setTimeout(() => {
                    button.textContent = originalText;
                    button.style.background = 'var(--accent-secondary)';
                }, 2000);
                
            } catch (err) {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = textToCopy;
                textArea.style.position = 'fixed';
                textArea.style.opacity = '0';
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();
                
                try {
                    document.execCommand('copy');
                    
                    const originalText = button.textContent;
                    button.textContent = 'Copied!';
                    button.style.background = 'var(--accent-primary)';
                    
                    setTimeout(() => {
                        button.textContent = originalText;
                        button.style.background = 'var(--accent-secondary)';
                    }, 2000);
                } catch (err) {
                    console.error('Failed to copy text: ', err);
                }
                
                document.body.removeChild(textArea);
            }
        });
    });

    // Smooth scrolling for anchor links
    const anchorLinks = document.querySelectorAll('a[href^="#"]');
    
    anchorLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            const href = link.getAttribute('href');
            
            if (href !== '#') {
                e.preventDefault();
                
                const target = document.querySelector(href);
                if (target) {
                    const offsetTop = target.offsetTop - 80; // Account for fixed header if any
                    
                    window.scrollTo({
                        top: offsetTop,
                        behavior: 'smooth'
                    });
                }
            }
        });
    });

    // Animate performance bars on scroll
    const observerOptions = {
        threshold: 0.5,
        rootMargin: '0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const perfFills = entry.target.querySelectorAll('.perf-fill');
                
                perfFills.forEach((fill, index) => {
                    setTimeout(() => {
                        fill.style.opacity = '1';
                        fill.style.transform = 'translateX(0)';
                    }, index * 200);
                });
                
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    const perfSection = document.querySelector('.performance');
    if (perfSection) {
        // Initially hide performance bars
        const perfFills = perfSection.querySelectorAll('.perf-fill');
        perfFills.forEach(fill => {
            fill.style.opacity = '0';
            fill.style.transform = 'translateX(-100%)';
            fill.style.transition = 'all 0.8s ease-out';
        });
        
        observer.observe(perfSection);
    }

    // GitHub Stars API call (optional - remove if you don't want external API calls)
    async function updateGitHubStats() {
        try {
            const response = await fetch('https://api.github.com/repos/dweekly/ftr');
            const data = await response.json();
            
            const starsElement = document.getElementById('github-stars');
            if (starsElement && data.stargazers_count) {
                starsElement.textContent = data.stargazers_count;
            }
        } catch (error) {
            console.log('Could not fetch GitHub stats:', error);
            // Silently fail - not critical functionality
        }
    }

    // Update GitHub stats on load
    updateGitHubStats();
});