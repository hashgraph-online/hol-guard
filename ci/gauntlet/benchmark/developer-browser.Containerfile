# Extend the exact locally captured base grader image, within the owned VM only.
FROM 827eaec482942aa5805beac1a75afd755b0daebade43024883b7d1637c27e52d
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/browser/browsers
RUN mkdir -p /opt/browser && cd /opt/browser && /usr/bin/npm install --ignore-scripts --no-audit --no-fund --save-exact playwright@1.58.2 && /usr/bin/node -e "const l=require('./package-lock.json'); if(l.packages['node_modules/playwright'].integrity !== 'sha512-vA30H8Nvkq/cPBnNw4Q8TWz1EJyqgpuinBcHET0YVJVFldr8JDNiU9LaWAE1KqSkRYazuaBhTpB5ZzShOezQ6A==') throw Error('Playwright package integrity differs')" && /usr/bin/node node_modules/playwright/cli.js install --with-deps chromium
USER 65532:65532
