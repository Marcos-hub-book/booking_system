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
const hamb = document.querySelector('.hamb');
const navLinks = document.querySelector('.nav-links');

if (hamb && navLinks) {
  hamb.addEventListener('click', () => {
    navLinks.classList.toggle('active');
  });
}

