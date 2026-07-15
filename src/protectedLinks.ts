const xeyeHref = 'https://xss.icu/';

export const protectedExternalLinks = Object.freeze({
  xeye: Object.freeze({
    label: 'Xeye',
    title: 'Xeye platform',
    href: xeyeHref,
  }),
});

export const isProtectedExternalUrl = (href: string | undefined) => href === xeyeHref;

export const openProtectedExternalLink = (href: string | undefined) => {
  if (!isProtectedExternalUrl(href)) return false;
  const opened = window.open(href, '_blank', 'noopener');
  if (opened) opened.opener = null;
  return true;
};
