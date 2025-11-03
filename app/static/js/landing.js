// Simples carrossel de depoimentos
let index = 0;
const depoimentos = document.querySelectorAll('.depoimento');

function mostrarDepoimento() {
  if (depoimentos.length === 0) return;
  depoimentos.forEach((dep, i) => {
    dep.classList.toggle('ativo', i === index);
  });
  index = (index + 1) % depoimentos.length;
}

setInterval(mostrarDepoimento, 4000);

// Opcional: Menu hamburger para mobile
const hamb = document.querySelector('.hamb'); // Supondo que você adicione a classe .hamb ao seu botão
const navLinks = document.querySelector('.nav-links');

if (hamb && navLinks) {
  hamb.addEventListener('click', () => {
    // Toggle display for nav-links, assuming it's initially hidden on mobile via CSS
    const isHidden = navLinks.style.display === 'none' || getComputedStyle(navLinks).display === 'none';
    navLinks.style.display = isHidden ? 'flex' : 'none';
  });
}

