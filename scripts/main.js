// Mobile Navigation
const hamburger = document.querySelector(".hamburger");
const navMenu = document.querySelector(".nav-menu");

hamburger.addEventListener("click", () => {
    hamburger.classList.toggle("active");
    navMenu.classList.toggle("active");
});

document.querySelectorAll(".nav-link").forEach(n => n.addEventListener("click", () => {
    hamburger.classList.remove("active");
    navMenu.classList.remove("active");
}));

// Script Tabs
const tabBtns = document.querySelectorAll(".tab-btn");
const tabContents = document.querySelectorAll(".tab-content");

tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
        // Remove active class from all buttons and contents
        tabBtns.forEach(btn => btn.classList.remove("active"));
        tabContents.forEach(content => content.classList.remove("active"));
        
        // Add active class to clicked button
        btn.classList.add("active");
        
        // Show corresponding content
        const tabId = btn.getAttribute("data-tab");
        document.getElementById(`${tabId}-content`).classList.add("active");
    });
});

// Plan Selection
const planBtns = document.querySelectorAll(".btn-plan");
planBtns.forEach(btn => {
    btn.addEventListener("click", () => {
        const plan = btn.getAttribute("data-plan");
        let ethAmount = 0.02;
        
        switch(plan) {
            case "basic":
                ethAmount = 0.02;
                break;
            case "pro":
                ethAmount = 0.02;
                break;
            case "enterprise":
                ethAmount = 0.05;
                break;
        }
        
        document.getElementById("eth-amount").textContent = ethAmount;
        
        // Scroll to payment section
        document.querySelector(".crypto-payment").scrollIntoView({
            behavior: "smooth"
        });
    });
});

// Copy Ethereum Address
function copyAddress() {
    const address = document.getElementById("eth-address").textContent;
    navigator.clipboard.writeText(address).then(() => {
        alert("Ethereum address copied to clipboard!");
    });
}

// Access Form Submission
document.getElementById("accessForm").addEventListener("submit", (e) => {
    e.preventDefault();
    alert("Access code submitted! If valid, you will be redirected to the content.");
    // In a real implementation, you would verify the code and redirect
});

// Smooth Scrolling for Navigation Links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const targetId = this.getAttribute('href');
        if (targetId === '#') return;
        
        const targetElement = document.querySelector(targetId);
        if (targetElement) {
            window.scrollTo({
                top: targetElement.offsetTop - 80,
                behavior: 'smooth'
            });
        }
    });
});
