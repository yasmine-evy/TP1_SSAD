document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.setAttribute('aria-selected', 'false'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.setAttribute('aria-selected', 'true');
    document.getElementById(tab.getAttribute('aria-controls')).classList.add('active');
  });
});

document.querySelectorAll('button.bar-head').forEach(head => {
  head.addEventListener('click', () => {
    const open = head.getAttribute('aria-expanded') === 'true';
    head.setAttribute('aria-expanded', String(!open));
  });
});