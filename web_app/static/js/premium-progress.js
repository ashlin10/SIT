/**
 * Minimalist Progress Bar
 * Clean, simple, and performant
 */

class PremiumProgressBar {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    if (!this.container) {
      console.error(`Container ${containerId} not found`);
      return;
    }
    
    this.bar = this.container.querySelector('.mini-progress-bar');
    this.fill = this.container.querySelector('.mini-progress-fill');
    this.text = this.container.querySelector('.mini-progress-text');
    this.label = this.container.querySelector('.mini-progress-label');
    this.spinner = this.container.querySelector('#mini-progress-spinner');
    
    this.currentProgress = 0;
    this.targetProgress = 0;
    this.animationFrame = null;
    
    this.config = {
      smoothingFactor: 0.15 // For smooth interpolation
    };
  }
  
  smoothProgress() {
    if (Math.abs(this.targetProgress - this.currentProgress) < 0.01) {
      this.currentProgress = this.targetProgress;
      if (this.animationFrame) {
        cancelAnimationFrame(this.animationFrame);
        this.animationFrame = null;
      }
    } else {
      // Smooth interpolation
      this.currentProgress += (this.targetProgress - this.currentProgress) * this.config.smoothingFactor;
    }
    
    // Update UI
    this.fill.style.width = `${this.currentProgress}%`;
    this.text.textContent = `${Math.round(this.currentProgress)}%`;
    if (this.bar) {
      this.bar.setAttribute('aria-valuenow', Math.round(this.currentProgress));
    }
    
    // Continue animation if not at target
    if (this.currentProgress !== this.targetProgress) {
      this.animationFrame = requestAnimationFrame(() => this.smoothProgress());
    }
  }
  
  /**
   * Set progress value (0-100, supports fractional values)
   * @param {number} value - Progress value
   * @param {string} label - Optional label text
   */
  setProgress(value, label = null) {
    this.targetProgress = Math.max(0, Math.min(100, value));
    
    if (label) {
      this.label.textContent = label;
    }
    
    // Start smooth animation
    if (!this.animationFrame) {
      this.animationFrame = requestAnimationFrame(() => this.smoothProgress());
    }
  }
  
  /**
   * Show the progress bar with animation
   * @param {string} label - Initial label text
   */
  show(label = 'Preparing...') {
    this.container.classList.remove('hidden');
    this.label.textContent = label;
    this.currentProgress = 0;
    this.targetProgress = 0;
    this.fill.style.width = '0%';
    this.text.textContent = '0%';
    if (this.bar) {
      this.bar.setAttribute('aria-valuenow', 0);
    }
    if (this.spinner) {
      this.spinner.classList.remove('hidden');
    }
  }
  
  /**
   * Hide the progress bar with animation
   */
  hide() {
    if (this.spinner) {
      this.spinner.classList.add('hidden');
    }
    setTimeout(() => {
      this.container.classList.add('hidden');
      this.currentProgress = 0;
      this.targetProgress = 0;
      
      // Stop animations
      if (this.animationFrame) {
        cancelAnimationFrame(this.animationFrame);
        this.animationFrame = null;
      }
    }, 500);
  }
  
  /**
   * Simulate progress animation with custom steps
   * @param {Array} steps - Array of {progress: number, label: string, duration: number}
   */
  async animateSteps(steps) {
    for (const step of steps) {
      this.setProgress(step.progress, step.label);
      await new Promise(resolve => setTimeout(resolve, step.duration));
    }
  }
  
  /**
   * Complete the progress with celebration effect
   */
  complete(label = 'Complete!') {
    this.setProgress(100, label);
    if (this.spinner) {
      this.spinner.classList.add('hidden');
    }
    setTimeout(() => {
      this.hide();
    }, 2000);
  }
  
  /**
   * Reset the progress bar
   */
  reset() {
    this.currentProgress = 0;
    this.targetProgress = 0;
    this.fill.style.width = '0%';
    this.text.textContent = '0%';
    if (this.bar) {
      this.bar.setAttribute('aria-valuenow', 0);
    }
  }
}

// Global instance
window.premiumProgress = null;

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  window.premiumProgress = new PremiumProgressBar('mini-progress-container');
  console.log('Minimalist Progress Bar initialized:', window.premiumProgress);
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = PremiumProgressBar;
}
