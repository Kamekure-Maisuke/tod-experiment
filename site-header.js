class SiteHeader extends HTMLElement {
    connectedCallback() {
        if (!document.getElementById("site-header-style")) {
            const style = document.createElement("style");
            style.id = "site-header-style";
            style.textContent = `
                .presence-dot {
                    display: inline-block;
                    width: 0.65em;
                    height: 0.65em;
                    border-radius: 50%;
                    background-color: var(--pico-muted-color);
                    vertical-align: middle;
                    transition: background-color 0.3s;
                }
                .presence-dot[data-status="online"] { background-color: #2eb67d; }
            `;
            document.head.appendChild(style);
        }

        this.innerHTML = `
            <header class="container" role="banner">
                <nav>
                    <ul>
                        <li><a href="/">ホーム</a></li>
                        <li><a href="/blogs/">ブログ</a></li>
                        <li><a href="/tools/">ツール</a></li>
                        <li aria-label="在席状況">
                            <span class="presence-dot" id="presence-dot" data-status="offline" role="img" aria-label="オフライン"></span>
                            <small id="presence-label">オフライン</small>
                        </li>
                    </ul>
                </nav>
            </header>
        `;
    }
}

customElements.define("site-header", SiteHeader);
