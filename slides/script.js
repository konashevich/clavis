document.addEventListener('DOMContentLoaded', () => {
    const viewport = document.createElement('div');
    viewport.id = 'presentation-viewport';
    document.body.appendChild(viewport);

    const thumbnailsContainer = document.getElementById('sidebar-thumbnails');
    const dotsContainer = document.getElementById('dots-container');
    const reorderToggle = document.getElementById('reorder-toggle');
    const reorderSave = document.getElementById('reorder-save');
    const reorderCancel = document.getElementById('reorder-cancel');
    const reorderReset = document.getElementById('reorder-reset');
    const reorderHint = document.getElementById('sidebar-reorder-hint');
    const sidebarStatus = document.getElementById('sidebar-status');
    const persistedOrder = Array.from(document.querySelectorAll('.slide-container')).map(slide => slide.id);
    const canUseServerFeatures = window.location.protocol === 'http:' || window.location.protocol === 'https:';

    let currentSlide = 0;
    let reorderMode = false;
    let reorderSnapshot = [];
    let draggedSlideId = null;
    let slideItems = [];
    let sourceFileHandle = null;
    let sourceHtmlCache = '';

    if (canUseServerFeatures) {
        reorderToggle.hidden = false;
    } else {
        reorderToggle.hidden = true;
        reorderSave.hidden = true;
        reorderCancel.hidden = true;
        reorderReset.hidden = true;
        reorderHint.hidden = true;
        sidebarStatus.hidden = true;
    }

    Array.from(document.querySelectorAll('.slide-container')).forEach((slide) => {
        const wrapper = document.createElement('div');
        wrapper.className = 'slide-wrapper';
        slide.parentNode.replaceChild(wrapper, slide);
        wrapper.appendChild(slide);
        viewport.appendChild(wrapper);

        const shortTitle = (slide.getAttribute('data-short-title') || '').trim();
        if (!shortTitle) {
            console.warn(`Slide ${slide.id} is missing data-short-title`);
        }
        slideItems.push({
            id: slide.id,
            slide,
            wrapper,
            titleText: shortTitle || slide.id
        });
    });

    renderNavigation();

    function resizeSlides() {
        const targetWidth = 1280;
        const targetHeight = 720;
        const scale = Math.min(window.innerWidth / targetWidth, window.innerHeight / targetHeight);
        document.querySelectorAll('.slide-container').forEach(slide => {
            slide.style.transform = `scale(${scale})`;
        });
    }

    window.addEventListener('resize', resizeSlides);
    resizeSlides();

    function updateNav() {
        slideItems.forEach((item, i) => {
            const w = item.wrapper;
            w.className = 'slide-wrapper';
            if (i < currentSlide) w.classList.add('prev');
            else if (i === currentSlide) w.classList.add('active');
            else w.classList.add('next');
        });

        dotsContainer.querySelectorAll('.dot').forEach((d, i) => {
            d.className = 'dot' + (i === currentSlide ? ' active' : '');
        });
        thumbnailsContainer.querySelectorAll('.thumbnail').forEach((t, i) => {
            t.className = 'thumbnail' + (i === currentSlide ? ' active' : '');
            if (reorderMode) t.classList.add('reorderable');
        });

        const activeThumb = thumbnailsContainer.querySelector('.thumbnail.active');
        if (activeThumb) activeThumb.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function renderNavigation() {
        thumbnailsContainer.innerHTML = '';
        dotsContainer.innerHTML = '';

        slideItems.forEach((item, index) => {
            const thumb = document.createElement('div');
            thumb.className = 'thumbnail';
            thumb.dataset.slideId = item.id;
            thumb.dataset.index = String(index);

            if (reorderMode) {
                thumb.classList.add('reorderable');
                thumb.setAttribute('draggable', 'true');
                thumb.innerHTML = `<span class="thumb-drag" aria-hidden="true"><i class="fa-solid fa-grip-vertical"></i></span><span class="thumb-number">${index + 1}</span><span class="thumb-title">${item.titleText}</span>`;
                attachReorderEvents(thumb);
            } else {
                thumb.innerHTML = `<span class="thumb-number">${index + 1}</span><span class="thumb-title">${item.titleText}</span>`;
                thumb.onclick = () => goToSlide(index);
            }
            thumbnailsContainer.appendChild(thumb);

            const dot = document.createElement('div');
            dot.className = 'dot';
            dot.title = item.titleText;
            dot.onclick = () => goToSlide(index);
            dotsContainer.appendChild(dot);
        });

        updateNav();
    }

    function attachReorderEvents(thumb) {
        thumb.addEventListener('dragstart', e => {
            draggedSlideId = thumb.dataset.slideId;
            thumb.classList.add('dragging');
            if (e.dataTransfer) {
                e.dataTransfer.effectAllowed = 'move';
                e.dataTransfer.setData('text/plain', draggedSlideId);
            }
        });

        thumb.addEventListener('dragover', e => {
            e.preventDefault();
            if (!draggedSlideId || draggedSlideId === thumb.dataset.slideId) {
                clearDropMarkers();
                return;
            }
            const rect = thumb.getBoundingClientRect();
            const placeAfter = e.clientY > rect.top + rect.height / 2;
            clearDropMarkers();
            thumb.classList.add(placeAfter ? 'drop-after' : 'drop-before');
        });

        thumb.addEventListener('dragleave', e => {
            if (e.relatedTarget && thumb.contains(e.relatedTarget)) return;
            thumb.classList.remove('drop-before', 'drop-after');
        });

        thumb.addEventListener('drop', e => {
            e.preventDefault();
            const fromIndex = slideItems.findIndex(item => item.id === draggedSlideId);
            const targetIndex = Number(thumb.dataset.index);
            if (fromIndex === -1 || targetIndex === -1) {
                clearDropMarkers();
                return;
            }
            const rect = thumb.getBoundingClientRect();
            const placeAfter = e.clientY > rect.top + rect.height / 2;
            let toIndex = targetIndex + (placeAfter ? 1 : 0);
            if (fromIndex < toIndex) toIndex -= 1;
            moveSlide(fromIndex, toIndex);
            clearDropMarkers();
        });

        thumb.addEventListener('dragend', () => {
            draggedSlideId = null;
            clearDropMarkers();
            thumbnailsContainer.querySelectorAll('.thumbnail').forEach(node => node.classList.remove('dragging'));
        });
    }

    function clearDropMarkers() {
        thumbnailsContainer.querySelectorAll('.thumbnail').forEach(node => {
            node.classList.remove('drop-before', 'drop-after');
        });
    }

    function moveSlide(fromIndex, toIndex) {
        if (fromIndex === toIndex || fromIndex < 0 || toIndex < 0 || toIndex > slideItems.length) return;
        const activeSlideId = slideItems[currentSlide] ? slideItems[currentSlide].id : null;
        const [moved] = slideItems.splice(fromIndex, 1);
        slideItems.splice(toIndex, 0, moved);
        syncViewportOrder();
        if (activeSlideId) currentSlide = slideItems.findIndex(item => item.id === activeSlideId);
        renderNavigation();
    }

    function syncViewportOrder() {
        const fragment = document.createDocumentFragment();
        slideItems.forEach(item => fragment.appendChild(item.wrapper));
        viewport.appendChild(fragment);
    }

    function setReorderMode(enabled) {
        reorderMode = enabled;
        reorderToggle.classList.toggle('is-active', enabled);
        reorderToggle.setAttribute('aria-pressed', enabled ? 'true' : 'false');
        reorderToggle.hidden = enabled;
        reorderSave.hidden = !enabled;
        reorderCancel.hidden = !enabled;
        reorderReset.hidden = !enabled;
        reorderHint.hidden = !enabled;
        document.body.classList.toggle('reorder-mode', enabled);
        if (!enabled) clearDropMarkers();
        renderNavigation();
    }

    function restoreOrder(orderIds) {
        const activeSlideId = slideItems[currentSlide] ? slideItems[currentSlide].id : null;
        const itemsById = new Map(slideItems.map(item => [item.id, item]));
        slideItems = orderIds.map(id => itemsById.get(id)).filter(Boolean);
        syncViewportOrder();
        if (activeSlideId) currentSlide = slideItems.findIndex(item => item.id === activeSlideId);
        renderNavigation();
    }

    function setStatus(message, tone = 'info') {
        sidebarStatus.hidden = false;
        sidebarStatus.className = `sidebar-status is-${tone}`;
        sidebarStatus.textContent = message;
    }

    function clearStatus() {
        sidebarStatus.hidden = true;
        sidebarStatus.textContent = '';
        sidebarStatus.className = 'sidebar-status';
    }

    async function getSourceHtml() {
        if (sourceHtmlCache) return sourceHtmlCache;
        const response = await fetch('index.html', { cache: 'no-store' });
        if (!response.ok) throw new Error('Unable to read index.html from the current page.');
        sourceHtmlCache = await response.text();
        return sourceHtmlCache;
    }

    function buildReorderedSource(sourceHtml) {
        const parser = new DOMParser();
        const sourceDoc = parser.parseFromString(sourceHtml, 'text/html');
        const sourceBody = sourceDoc.body;
        const menuToggle = sourceDoc.getElementById('menu-toggle');
        if (!menuToggle) throw new Error('Unable to find the sidebar UI anchor in index.html.');

        const slidesById = new Map(
            Array.from(sourceBody.querySelectorAll(':scope > .slide-container'))
                .map(slide => [slide.id, slide])
        );
        const orderedSlides = [];
        slideItems.forEach(item => {
            const slide = slidesById.get(item.id);
            if (slide) orderedSlides.push(slide);
        });
        if (orderedSlides.length !== slideItems.length) {
            throw new Error('Unable to map the current slide order back onto index.html.');
        }
        const fragment = sourceDoc.createDocumentFragment();
        orderedSlides.forEach(slide => fragment.appendChild(slide));
        sourceBody.insertBefore(fragment, menuToggle);
        return '<!DOCTYPE html>\n' + sourceDoc.documentElement.outerHTML;
    }

    async function getWritableHandle() {
        if (sourceFileHandle) return sourceFileHandle;
        if (typeof window.showOpenFilePicker !== 'function') {
            throw new Error('This browser cannot write files directly. Use a Chromium-based browser for in-place saves.');
        }
        const [handle] = await window.showOpenFilePicker({
            multiple: false,
            types: [{ description: 'HTML files', accept: { 'text/html': ['.html'] } }]
        });
        if (typeof handle.requestPermission === 'function') {
            const permission = await handle.requestPermission({ mode: 'readwrite' });
            if (permission !== 'granted') throw new Error('Write permission was not granted.');
        }
        sourceFileHandle = handle;
        return handle;
    }

    async function saveOrderToSource() {
        setStatus('Saving slide order to index.html...', 'info');
        reorderSave.disabled = true;
        try {
            const sourceHtml = await getSourceHtml();
            const reorderedHtml = buildReorderedSource(sourceHtml);
            const handle = await getWritableHandle();
            const writable = await handle.createWritable();
            await writable.write(reorderedHtml);
            await writable.close();
            sourceHtmlCache = reorderedHtml;
            persistedOrder.length = 0;
            slideItems.forEach(item => persistedOrder.push(item.id));
            setStatus('Saved slide order to slides/index.html.', 'success');
            setReorderMode(false);
        } catch (error) {
            setStatus(error.message || 'Failed to save the new slide order.', 'error');
        } finally {
            reorderSave.disabled = false;
        }
    }

    window.nextSlide = function () {
        if (currentSlide < slideItems.length - 1) {
            currentSlide++;
            updateNav();
        }
    };

    window.prevSlide = function () {
        if (currentSlide > 0) {
            currentSlide--;
            updateNav();
        }
    };

    window.goToSlide = function (index) {
        currentSlide = index;
        updateNav();
    };

    reorderToggle.addEventListener('click', () => {
        reorderSnapshot = slideItems.map(item => item.id);
        clearStatus();
        setReorderMode(true);
    });
    reorderSave.addEventListener('click', async () => { await saveOrderToSource(); });
    reorderCancel.addEventListener('click', () => {
        if (reorderSnapshot.length) restoreOrder(reorderSnapshot);
        clearStatus();
        setReorderMode(false);
    });
    reorderReset.addEventListener('click', () => {
        restoreOrder(persistedOrder);
        setStatus('Restored the last saved slide order.', 'info');
    });

    updateNav();

    let isScrolling = false;
    window.addEventListener('wheel', (e) => {
        if (document.getElementById('sidebar').contains(e.target)) return;
        if (isScrolling) return;
        if (e.deltaY !== 0) {
            isScrolling = true;
            if (e.deltaY > 0) nextSlide();
            else prevSlide();
            setTimeout(() => { isScrolling = false; }, 1100);
        }
    }, { passive: false });

    window.addEventListener('keydown', (e) => {
        const activeTag = document.activeElement ? document.activeElement.tagName : '';
        if (['INPUT', 'TEXTAREA', 'SELECT', 'BUTTON'].includes(activeTag)) return;
        if (['ArrowDown', 'ArrowRight', 'PageDown', ' '].includes(e.key)) {
            e.preventDefault();
            nextSlide();
        } else if (['ArrowUp', 'ArrowLeft', 'PageUp'].includes(e.key)) {
            e.preventDefault();
            prevSlide();
        }
    });

    let touchStartY = 0;
    window.addEventListener('touchstart', e => { touchStartY = e.touches[0].clientY; }, { passive: true });
    window.addEventListener('touchend', e => {
        const diffY = touchStartY - e.changedTouches[0].clientY;
        if (Math.abs(diffY) > 50) {
            if (diffY > 0) nextSlide();
            else prevSlide();
        }
    }, { passive: true });
});

let sidebarOpen = false;
window.toggleSidebar = function () {
    sidebarOpen = !sidebarOpen;
    document.getElementById('sidebar').classList.toggle('open', sidebarOpen);
    document.body.classList.toggle('drawer-open', sidebarOpen);
    const menuIcon = document.querySelector('#menu-toggle i');
    if (sidebarOpen) {
        menuIcon.classList.remove('fa-bars');
        menuIcon.classList.add('fa-xmark');
    } else {
        menuIcon.classList.remove('fa-xmark');
        menuIcon.classList.add('fa-bars');
    }
};
