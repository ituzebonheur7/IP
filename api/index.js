const geoip = require('geoip-lite');

module.exports = async (req, res) => {
  try {
    // Get client IP from request
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() ||
                     req.headers['x-real-ip'] ||
                     req.socket.remoteAddress ||
                     '127.0.0.1';

    // Get geolocation from IP
    const geo = geoip.lookup(clientIp);

    // Extract IPv6 if available
    const ipv6 = req.socket.remoteAddress?.includes(':') ? req.socket.remoteAddress : '';

    // Build response matching schema
    const data = {
      ip: clientIp,
      ipv6: ipv6 || '',
      postal: geo?.zip || '',
      timezone: geo?.timezone || '',
      utc_offset: getUtcOffset(geo?.timezone) || '',
      languages: geo?.country ? getLanguagesByCountry(geo.country) : '',
      asn: geo?.asn?.asn || '',
      org: geo?.asn?.org || ''
    };

    res.status(200).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

function getUtcOffset(timezone) {
  if (!timezone) return '';
  try {
    const now = new Date();
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      timeZoneName: 'longOffset'
    });
    const parts = formatter.formatToParts(now);
    const offset = parts.find(p => p.type === 'timeZoneName');
    return offset?.value || '';
  } catch {
    return '';
  }
}

function getLanguagesByCountry(countryCode) {
  // Map of country codes to primary languages
  const languageMap = {
    'US': 'en', 'GB': 'en', 'CA': 'en', 'AU': 'en',
    'FR': 'fr', 'DE': 'de', 'ES': 'es', 'IT': 'it',
    'JP': 'ja', 'CN': 'zh', 'RU': 'ru', 'BR': 'pt',
    'MX': 'es', 'IN': 'en', 'ZA': 'en', 'KR': 'ko'
  };
  return languageMap[countryCode] || '';
}
