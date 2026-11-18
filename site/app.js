// Vitrine Mini-SIEM : affiche l'instantané des données (data/*.json) exporté depuis l'API du labo.
// Sécurité : les "preuves" contiennent de vraies charges d'attaque (<script>…). On les insère
// TOUJOURS avec textContent, jamais avec innerHTML : elles s'affichent comme du texte, sans s'exécuter.

const REGLES = ["R1_brute_force", "R2_injection_sql", "R3_xss", "R4_scan", "R5_traversal"];
const NOMS = {
  R1_brute_force: "R1 brute force", R2_injection_sql: "R2 injection SQL", R3_xss: "R3 XSS",
  R4_scan: "R4 scan", R5_traversal: "R5 remontée de dossiers",
};
// Même couleur fixe par règle que dans le dashboard Streamlit
const COULEURS = {
  R1_brute_force: "#2a78d6", R2_injection_sql: "#eb6834", R3_xss: "#1baf7a",
  R4_scan: "#eda100", R5_traversal: "#e87ba4",
};
const SURFACE = "#ffffff";

function cellule(ligne, texte, classe) {
  const td = document.createElement("td");
  if (classe) td.className = classe;
  td.textContent = texte;
  ligne.appendChild(td);
  return td;
}

function heureLisible(iso) {
  const d = new Date(iso + "Z");
  const deux = n => String(n).padStart(2, "0");
  return `${deux(d.getUTCDate())}/${deux(d.getUTCMonth() + 1)} ${deux(d.getUTCHours())}:${deux(d.getUTCMinutes())}:${deux(d.getUTCSeconds())}`;
}

// Petit plugin : écrit la valeur au bout de chaque barre horizontale
const valeursAuBout = {
  id: "valeursAuBout",
  afterDatasetsDraw(chart) {
    const { ctx } = chart;
    ctx.save();
    ctx.fillStyle = "#52514e";
    ctx.font = "12px Segoe UI, Arial, sans-serif";
    ctx.textBaseline = "middle";
    chart.getDatasetMeta(0).data.forEach((barre, i) => {
      ctx.fillText(chart.data.datasets[0].data[i], barre.x + 6, barre.y);
    });
    ctx.restore();
  },
};

function graphiqueRegles(stats) {
  const nb = Object.fromEntries(stats.alertes_par_regle.map(r => [r.regle, r.nb]));
  new Chart(document.getElementById("g-regles"), {
    type: "bar",
    data: {
      labels: REGLES.map(r => NOMS[r]),
      datasets: [{
        data: REGLES.map(r => nb[r] || 0),
        backgroundColor: REGLES.map(r => COULEURS[r]),
        borderColor: SURFACE, borderWidth: 2, borderRadius: 4, barPercentage: 0.6,
      }],
    },
    options: {
      indexAxis: "y", maintainAspectRatio: false,
      layout: { padding: { right: 28 } },
      plugins: { legend: { display: false } },
      scales: { x: { grid: { color: "#ebeae6" }, ticks: { precision: 0 } }, y: { grid: { display: false } } },
    },
    plugins: [valeursAuBout],
  });
}

function graphiqueHeures(stats) {
  // tri sur la vraie date AVANT de transformer en texte (sinon l'ordre peut être faux)
  const heures = [...new Set(stats.alertes_par_heure.map(h => h.heure))].sort();
  const etiquette = iso => { const d = new Date(iso + "Z"); return `${d.getUTCDate()}/${d.getUTCMonth() + 1} ${d.getUTCHours()}h`; };
  new Chart(document.getElementById("g-heures"), {
    type: "bar",
    data: {
      labels: heures.map(etiquette),
      datasets: REGLES.map(regle => ({
        label: NOMS[regle],
        data: heures.map(h => (stats.alertes_par_heure.find(x => x.heure === h && x.regle === regle) || {}).nb || 0),
        backgroundColor: COULEURS[regle], borderColor: SURFACE, borderWidth: 2, barPercentage: 0.55,
      })),
    },
    options: {
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { position: "bottom", labels: { boxWidth: 12, boxHeight: 12 } } },
      scales: { x: { stacked: true, grid: { display: false } },
                y: { stacked: true, grid: { color: "#ebeae6" }, ticks: { precision: 0 } } },
    },
  });
}

function tableauIp(stats) {
  const corps = document.querySelector("#t-ip tbody");
  const max = Math.max(...stats.top_ip.map(x => x.nb_alertes));
  stats.top_ip.forEach(x => {
    const tr = document.createElement("tr");
    cellule(tr, x.ip);
    const td = cellule(tr, "");
    const barre = document.createElement("div"); barre.className = "barre";
    const trait = document.createElement("i"); trait.style.width = `${Math.round(90 * x.nb_alertes / max)}px`;
    const nombre = document.createElement("span"); nombre.textContent = x.nb_alertes;
    barre.append(trait, nombre); td.appendChild(barre);
    cellule(tr, x.nb_requetes, "nombre");
    cellule(tr, x.regles.split(", ").map(r => NOMS[r] || r).join(", "));
    corps.appendChild(tr);
  });
}

function tableauAlertes(alertes) {
  const corps = document.querySelector("#t-alertes tbody");
  const choixRegle = document.getElementById("f-regle");
  const choixGravite = document.getElementById("f-gravite");
  REGLES.forEach(r => { const o = document.createElement("option"); o.value = r; o.textContent = NOMS[r]; choixRegle.appendChild(o); });

  function afficher() {
    corps.replaceChildren();
    const liste = alertes.filter(a => (!choixRegle.value || a.regle === choixRegle.value) &&
                                      (!choixGravite.value || a.gravite === choixGravite.value));
    liste.forEach(a => {
      const tr = document.createElement("tr");
      cellule(tr, heureLisible(a.horodatage));
      const tdRegle = cellule(tr, "");
      const point = document.createElement("span"); point.className = "pastille"; point.style.background = COULEURS[a.regle];
      tdRegle.append(point, document.createTextNode(NOMS[a.regle]));
      cellule(tr, a.gravite, `gravite-${a.gravite}`);
      cellule(tr, a.ip);
      cellule(tr, a.preuve, "preuve");               // texte brut : la charge d'attaque ne s'exécute pas
      corps.appendChild(tr);
    });
    document.getElementById("f-compte").textContent = `${liste.length} alerte(s)`;
  }
  choixRegle.addEventListener("change", afficher);
  choixGravite.addEventListener("change", afficher);
  afficher();
}

async function demarrer() {
  const [stats, alertes] = await Promise.all([
    fetch("data/stats.json").then(r => r.json()),
    fetch("data/alertes.json").then(r => r.json()),
  ]);
  document.getElementById("k-requetes").textContent = stats.nb_requetes;
  document.getElementById("k-ip").textContent = stats.nb_ip;
  document.getElementById("k-alertes").textContent = stats.nb_alertes;
  document.getElementById("k-hautes").textContent =
    (stats.alertes_par_gravite.find(g => g.gravite === "haute") || {}).nb || 0;
  if (window.Chart) {
    Chart.defaults.font.family = "Segoe UI, system-ui, Arial, sans-serif";
    Chart.defaults.color = "#52514e";
    graphiqueRegles(stats);
    graphiqueHeures(stats);
  }
  tableauIp(stats);
  tableauAlertes(alertes);
}

demarrer().catch(err => console.error("Données indisponibles", err));
