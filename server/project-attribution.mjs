import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const attribution = require('./project-attribution.cjs');

export const clientProjectRoute = attribution.clientProjectRoute;
export const officialProjectUrl = attribution.officialProjectUrl;
export const publicProjectRoute = attribution.publicProjectRoute;
export const resolveProjectAttribution = attribution.resolveProjectAttribution;
