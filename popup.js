let i18n = {};
let currentSortAsc = true;
let currentTabDomain = null;

/**
 * Экранирует HTML-спецсимволы для предотвращения XSS
 * @param {string} str - Строка для экранирования
 * @returns {string} Экранированная строка
 */
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '<')
    .replace(/>/g, '>')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Проверяет, является ли строка валидным хостом (доменом или IP-адресом)
 * Поддерживает: example.com, sub.example.com, localhost, 192.168.1.1
 * Не поддерживает: порты, пути, протоколы, звёздочки, пустые строки
 */
function isValidHost(host) {
  if (!host || typeof host !== 'string') return false;
  
  const trimmed = host.trim().toLowerCase();
  if (!trimmed || trimmed.length > 253) return false;

  // Проверка на IPv4
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  if (ipv4Regex.test(trimmed)) {
    return trimmed.split('.').every(part => {
      const num = parseInt(part, 10);
      return num >= 0 && num <= 255;
    });
  }

  // Проверка на доменное имя или localhost
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  return domainRegex.test(trimmed) && trimmed !== '.';
}

/**
 * Обновляет состояние кнопок в зависимости от наличия заблокированных доменов
 * @param {string[]} blockedList - Список заблокированных доменов
 */
function updateButtonStates(blockedList) {
  const isEmpty = !blockedList || blockedList.length === 0;
  const clearAllBtn = document.getElementById('clearAllBtn');
  const exportBtn = document.getElementById('exportBtn');
  
  if (clearAllBtn) clearAllBtn.disabled = isEmpty;
  if (exportBtn) exportBtn.disabled = isEmpty;
}

/**
 * Загружает языковой файл из папки `locales`
 * @param {string} lang - Код языка (например, 'ru', 'en')
 */
function loadLanguage(lang = 'ru') {
  fetch(`locales/${lang}.json`)
    .then(response => response.ok ? response.json() : Promise.reject())
    .then(data => {
      i18n = data;
      applyTranslations();
      initializePopup();
    })
    .catch(() => {
      i18n = getFallbackTranslations(lang);
      applyTranslations();
      initializePopup();
    });
}

/**
 * Возвращает резервные переводы на случай ошибки загрузки
 * @param {string} lang - Код языка
 * @returns {Object} Объект с переводами
 */
function getFallbackTranslations(lang) {
  if (lang === 'en') {
    return {
      title: 'JS Blocker',
      site: 'Site',
      status: 'Status',
      js_blocked: 'Blocked',
      js_allowed: 'Allowed',
      toggle_block: 'Block JS',
      toggle_allow: 'Allow JS',
      toggle_title: 'Toggle JavaScript blocking',
      blocked_sites: 'Blocked sites',
      clear_all: 'Clear all',
      clear_all_title: 'Clear entire blocked list',
      export_title: 'Export blocked domains',
      import_title: 'Import blocked domains',
      sort_title: 'Toggle sort order',
      search_label: 'Search by domain',
      search_help: 'Enter part of a domain to filter the list',
      search_header: 'Search',
      search_placeholder: 'Search domains...',
      sort: 'Sort',
      delete_domain: 'Delete',
      empty_list: 'List is empty',
      confirm_clear_all: 'Clear entire list?',
      export: 'Export',
      import: 'Import',
      import_success: 'Domains imported: {count}',
      import_error: 'Import error:',
      import_error_format: 'Expected an array of domains',
      import_invalid_skipped: 'Skipped invalid entries',
      export_started: 'Export started — check save dialog',
      current_site: 'Current site',
      internal_page: 'Not available on browser internal pages',
      lang: 'en'
    };
  }

  return {
    title: 'Блокировщик JS',
    site: 'Сайт',
    status: 'Статус',
    js_blocked: 'Заблокирован',
    js_allowed: 'Разрешён',
    toggle_block: 'Отключить JS',
    toggle_allow: 'Разрешить JS',
    toggle_title: 'Переключить блокировку JavaScript',
    blocked_sites: 'Заблокированные сайты',
    clear_all: 'Очистить всё',
    clear_all_title: 'Очистить весь список заблокированных доменов',
    export_title: 'Экспорт заблокированных доменов',
    import_title: 'Импорт заблокированных доменов',
    sort_title: 'Переключить порядок сортировки',
    search_label: 'Поиск по домену',
    search_help: 'Введите часть домена для фильтрации списка',
    search_header: 'Поиск',
    search_placeholder: 'Поиск по доменам...',
    sort: 'Сортировать',
    delete_domain: 'Удалить',
    empty_list: 'Список пуст',
    confirm_clear_all: 'Очистить весь список?',
    export: 'Экспорт',
    import: 'Импорт',
    import_success: 'Импортировано доменов: {count}',
    import_error: 'Ошибка импорта:',
    import_error_format: 'Ожидался массив доменов',
    import_invalid_skipped: 'Пропущено недопустимых записей',
    export_started: 'Экспорт начат — проверьте окно сохранения',
    current_site: 'Текущий сайт',
    internal_page: 'Недоступно на внутренних страницах браузера',
    lang: 'ru'
  };
}

/**
 * Применяет переводы ко всем элементам интерфейса
 */
function applyTranslations() {
  document.documentElement.lang = i18n.lang || 'ru';
  document.title = i18n.title || 'JS Blocker';

  const elements = {
    toggleBtn: { text: 'toggle_block', title: 'toggle_title' },
    clearAllBtn: { text: 'clear_all', title: 'clear_all_title' },
    blockedSitesHeader: { text: 'blocked_sites' },
    exportBtn: { text: 'export', title: 'export_title' },
    importBtn: { text: 'import', title: 'import_title' },
    searchHeader: { text: 'search_header' },
    searchInput: { placeholder: 'search_placeholder' },
    sortBtn: { text: 'sort', title: 'sort_title' }
  };

  if (i18n.search_label) {
    const label = document.getElementById('searchLabel');
    if (label) label.textContent = i18n.search_label;
  }
  if (i18n.search_help) {
    const help = document.getElementById('searchHelp');
    if (help) help.textContent = i18n.search_help;
  }

  for (const [id, props] of Object.entries(elements)) {
    const el = document.getElementById(id);
    if (!el) continue;

    if (props.text && i18n[props.text]) {
      el.textContent = i18n[props.text];
    }
    if (props.title && i18n[props.title]) {
      el.title = i18n[props.title];
      el.setAttribute('aria-label', i18n[props.title]);
    }
    if (props.placeholder && i18n[props.placeholder]) {
      el.placeholder = i18n[props.placeholder];
    }
  }
}

/**
 * Извлекает домен из URL, игнорируя внутренние страницы браузера
 * @param {string} url - URL страницы
 * @returns {string|null} Хостнейм или null
 */
function getDomainFromUrl(url) {
  try {
    const parsed = new URL(url);
    if (['chrome:', 'edge:', 'about:', '', 'blob:'].includes(parsed.protocol)) {
      return null;
    }
    return parsed.hostname;
  } catch {
    return null;
  }
}

/**
 * Отображает список заблокированных доменов
 * @param {string[]} blacklist - Список заблокированных доменов
 */
function renderBlockedList(blacklist) {
  const list = document.getElementById('blockedList');
  if (!list) return;

  const sorted = [...blacklist].sort((a, b) =>
    currentSortAsc ? a.localeCompare(b) : b.localeCompare(a)
  );

  list.innerHTML = '';

  if (sorted.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'empty';
    empty.setAttribute('role', 'listitem');
    empty.textContent = i18n.empty_list || 'Список пуст';
    list.appendChild(empty);
    return;
  }

  const query = document.getElementById('searchInput')?.value.trim().toLowerCase() || '';

  sorted.forEach((domain) => {
    const li = document.createElement('li');
    li.setAttribute('role', 'listitem');

    if (domain === currentTabDomain) {
      li.classList.add('current-domain');
      li.title = i18n.current_site || 'Текущий сайт';
    }

    const span = document.createElement('span');
    if (query && domain.toLowerCase().includes(query)) {
      const idx = domain.toLowerCase().indexOf(query);
      const before = escapeHtml(domain.slice(0, idx));
      const match = escapeHtml(domain.slice(idx, idx + query.length));
      const after = escapeHtml(domain.slice(idx + query.length));
      span.innerHTML = `${before}<strong>${match}</strong>${after}`;
    } else {
      span.textContent = domain;
    }

    const btn = document.createElement('button');
    btn.textContent = `🗑 ${i18n.delete_domain || 'Удалить'}`;
    btn.classList.add('danger');
    btn.setAttribute('aria-label', `${i18n.delete_domain || 'Удалить'} ${domain}`);
    btn.onclick = () => {
      li.classList.add('fade-out');
      btn.disabled = true;
      setTimeout(() => {
        const updated = blacklist.filter((d) => d !== domain);
        chrome.storage.local.set({ blacklist: updated }, () => {
          chrome.runtime.sendMessage({ type: 'updateContextMenu' });
          chrome.runtime.sendMessage({ type: 'updatePopup' });

          const searchInput = document.getElementById('searchInput');
          const currentQuery = searchInput?.value.trim().toLowerCase() || '';
          const filtered = updated.filter(d => d.toLowerCase().includes(currentQuery));
          renderBlockedList(filtered);
          updateButtonStates(filtered);
        });
      }, 300);
    };

    li.appendChild(span);
    li.appendChild(btn);
    list.appendChild(li);
  });
}

/**
 * Дебаунс для отложенного выполнения функции
 * @param {Function} func - Функция для вызова
 * @param {number} delay - Задержка в миллисекундах
 * @returns {Function} Обёрнутая функция
 */
function debounce(func, delay) {
  let timeoutId;
  return function (...args) {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func.apply(this, args), delay);
  };
}

/**
 * Показывает временное уведомление (toast)
 * @param {string} message - Текст уведомления
 */
function showToast(message) {
  const toast = document.createElement('div');
  toast.textContent = message;
  toast.className = 'toast';
  toast.setAttribute('aria-live', 'polite');
  document.body.appendChild(toast);
  toast.classList.add('fade-in');

  setTimeout(() => {
    toast.classList.add('fade-out');
    setTimeout(() => {
      if (toast.parentNode) toast.remove();
    }, 300);
  }, 2700);
}

/**
 * Инициализирует логику popup-окна
 */
function initializePopup() {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const tab = tabs[0];
    const domain = tab?.url ? getDomainFromUrl(tab.url) : null;

    const domainEl = document.getElementById('domain');
    const statusEl = document.getElementById('status');
    const toggleBtn = document.getElementById('toggleBtn');
    const actionSection = toggleBtn?.closest('section');

    // Обработка внутренних страниц браузера
    if (!domain || !tab?.url) {
      // Скрываем элементы, относящиеся к текущему сайту
      if (domainEl) domainEl.style.display = 'none';
      if (statusEl) statusEl.style.display = 'none';
      if (actionSection) actionSection.style.display = 'none';

      // Удаляем старое сообщение, если есть
      const oldMsg = document.getElementById('internal-page-message');
      if (oldMsg) oldMsg.remove();

      // Добавляем поясняющее сообщение
      const message = document.createElement('p');
      message.id = 'internal-page-message';
      message.textContent = i18n.internal_page || 'Недоступно на этой странице';

      const main = document.querySelector('main');
      const firstHeader = document.querySelector('h2');
      if (main && firstHeader) {
        main.insertBefore(message, firstHeader);
      }

      // Отображаем список заблокированных доменов
      chrome.storage.local.get(['blacklist'], data => {
        const blacklist = data.blacklist || [];
        renderBlockedList(blacklist);
        updateButtonStates(blacklist);
      });

      return;
    }

    // === Обычная логика для валидных внешних сайтов ===
    currentTabDomain = domain;

    if (domainEl) {
      domainEl.textContent = `${i18n.site || 'Сайт'}: ${domain}`;
      domainEl.style.display = 'block';
    }

    chrome.storage.local.get(['blacklist'], data => {
      const blacklist = data.blacklist || [];
      const isBlocked = blacklist.includes(domain);

      if (statusEl) {
        const icon = isBlocked ? '⛔' : '✅';
        const statusText = isBlocked
          ? i18n.js_blocked || 'Заблокирован'
          : i18n.js_allowed || 'Разрешён';
        statusEl.innerHTML = `${icon} ${i18n.status || 'Статус'}: ${statusText}`;
        statusEl.title = isBlocked 
          ? (i18n.js_blocked_hint || 'JavaScript заблокирован на этом сайте')
          : (i18n.js_allowed_hint || 'JavaScript разрешён на этом сайте');
        
        statusEl.classList.remove('blocked', 'allowed', 'fade-out', 'fade-in');
        statusEl.classList.add(isBlocked ? 'blocked' : 'allowed');
        statusEl.style.display = 'block';
      }

      if (toggleBtn) {
        toggleBtn.textContent = isBlocked
          ? (i18n.toggle_allow || 'Разрешить JS')
          : (i18n.toggle_block || 'Отключить JS');
        toggleBtn.title = i18n.toggle_title || 'Переключить статус блокировки';
        toggleBtn.classList.remove('allow', 'block');
        toggleBtn.classList.add(isBlocked ? 'block' : 'allow');
        toggleBtn.disabled = false;
        toggleBtn.style.display = 'block';

        toggleBtn.onclick = () => {
          toggleBtn.disabled = true;
          if (statusEl) {
            statusEl.classList.add('fade-out');
          }

          chrome.runtime.sendMessage(
            { 
              type: 'toggleBlock', 
              tabId: tab.id, 
              url: tab.url
            },
            () => {
              setTimeout(() => {
                window.close();
              }, 300);
            }
          );
        };
      }

      if (actionSection) {
        actionSection.style.display = 'block';
      }

      // Убираем сообщение, если оно было
      const msg = document.getElementById('internal-page-message');
      if (msg) msg.remove();

      renderBlockedList(blacklist);
      updateButtonStates(blacklist);
    });
  });

  // === Поиск ===
  const searchInput = document.getElementById('searchInput');
  if (searchInput) {
    searchInput.oninput = debounce(e => {
      const query = e.target.value.toLowerCase();
      chrome.storage.local.get(['blacklist'], data => {
        const filtered = (data.blacklist || []).filter(d => d.toLowerCase().includes(query));
        renderBlockedList(filtered);
        updateButtonStates(filtered);
      });
    }, 300);
  }

  // === Сортировка ===
  const sortBtn = document.getElementById('sortBtn');
  if (sortBtn) {
    sortBtn.onclick = () => {
      currentSortAsc = !currentSortAsc;
      sortBtn.textContent = currentSortAsc
        ? `🔼 ${i18n.sort || 'Сортировать'}`
        : `🔽 ${i18n.sort || 'Сортировать'}`;

      const query = document.getElementById('searchInput')?.value.trim().toLowerCase() || '';
      chrome.storage.local.get(['blacklist'], data => {
        let list = data.blacklist || [];
        if (query) list = list.filter(d => d.toLowerCase().includes(query));
        renderBlockedList(list);
        updateButtonStates(list);
      });
    };
  }

  // === Очистка всего списка ===
  const clearBtn = document.getElementById('clearAllBtn');
  if (clearBtn) {
    clearBtn.onclick = () => {
      if (confirm(i18n.confirm_clear_all || 'Очистить весь список?')) {
        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
          const currentDomain = tabs[0] ? getDomainFromUrl(tabs[0].url) : null;
          chrome.storage.local.get(['blacklist'], data => {
            const wasBlocked = currentDomain && (data.blacklist || []).includes(currentDomain);

            chrome.storage.local.set({ blacklist: [] }, () => {
              renderBlockedList([]);
              updateButtonStates([]);
              chrome.runtime.sendMessage({ type: 'updateContextMenu' });
              chrome.runtime.sendMessage({ type: 'updatePopup' });

              if (wasBlocked && tabs[0]?.id) {
                chrome.tabs.reload(tabs[0].id, { bypassCache: true });
              }
            });
          });
        });
      }
    };
  }

  // === Экспорт ===
  const exportBtn = document.getElementById('exportBtn');
  if (exportBtn) {
    exportBtn.onclick = () => {
      chrome.storage.local.get(['blacklist'], data => {
        const json = JSON.stringify(data.blacklist || [], null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        chrome.downloads.download({
          url,
          filename: 'blacklist.json',
          saveAs: true
        }, () => {
          URL.revokeObjectURL(url);
          showToast(i18n.export_started || 'Экспорт начат — проверьте окно сохранения');
        });
      });
    };
  }

  // === Импорт ===
  const importBtn = document.getElementById('importBtn');
  const importFile = document.getElementById('importFile');
  if (importBtn && importFile) {
    importBtn.onclick = () => importFile.click();

    importFile.onchange = e => {
      const file = e.target.files?.[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = () => {
        try {
          const data = JSON.parse(reader.result);
          if (!Array.isArray(data)) throw new Error(i18n.import_error_format || 'Expected a JSON array');

          // Фильтруем и валидируем
          const validDomains = [];
          const invalidCount = 0;

          for (const item of data) {
            if (typeof item === 'string' && isValidHost(item)) {
              validDomains.push(item.trim().toLowerCase());
            }
            // Иначе — игнорируем (можно логировать, но не будем)
          }

          const cleaned = [...new Set(validDomains)]; // Удаляем дубли

          chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
            const currentDomain = tabs[0] ? getDomainFromUrl(tabs[0].url) : null;
            const shouldReload = currentDomain && cleaned.includes(currentDomain.toLowerCase());

            chrome.storage.local.set({ blacklist: cleaned }, () => {
              chrome.runtime.sendMessage({ type: 'updatePopup' });
              renderBlockedList(cleaned);
              updateButtonStates(cleaned);

              if (shouldReload && tabs[0]?.id) {
                chrome.tabs.reload(tabs[0].id, { bypassCache: true });
              }

              const msg = (i18n.import_success || 'Imported domains: {count}')
                .replace('{count}', cleaned.length);
              showToast(msg);

              // Опционально: покажем, сколько было отброшено
              const invalid = data.length - validDomains.length;
              if (invalid > 0) {
                const warnMsg = `${i18n.import_invalid_skipped || 'Skipped invalid entries'}: ${invalid}`;
                showToast(warnMsg);
              }
            });
          });
        } catch (err) {
          showToast(`${i18n.import_error || 'Import error:'} ${err.message}`);
        }
      };
      reader.readAsText(file);
    };
  }

  // === Обновление popup по сообщению ===
  chrome.runtime.onMessage.addListener(message => {
    if (message.type === 'refreshPopup') {
      location.reload();
    }
  });

  // Фокус на поиск при открытии (если поле видимо)
  if (searchInput) searchInput.focus();
}

// --- Запуск после загрузки DOM ---
document.addEventListener('DOMContentLoaded', () => {
  chrome.storage.local.get(['lang'], data => {
    const userLang = data.lang || navigator.language.slice(0, 2);
    const finalLang = ['ru', 'en'].includes(userLang) ? userLang : 'ru';
    loadLanguage(finalLang);
  });
});
