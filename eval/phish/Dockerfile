# Sandbox for visiting live phishing pages: headless Chromium in a container,
# running as an unprivileged user. Built and run by eval/phish/run.mjs.
FROM mcr.microsoft.com/playwright:v1.57.0-noble
WORKDIR /harness
RUN npm init -y >/dev/null && npm install --no-audit --no-fund playwright@1.57.0
COPY capture.mjs /harness/capture.mjs
USER pwuser
ENTRYPOINT ["node", "/harness/capture.mjs"]
