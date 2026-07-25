const geoip = require('geoip-lite');
const ip6addr = require('ip6addr');

module.exports = async (req, res) => {
  try {
    // Get client IP from request
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() ||
                     req.headers['x-real-ip'] ||
                     req.socket.remoteAddress ||
                     '127.0.0.1';

    // Get geolocation from IP
    const geo = geoip.lookup(clientIp);

    // Extract IPv6 address
    const ipv6 = getIPv6(req);

    // Get ASN and organization info
    const asnInfo = getASNInfo(clientIp, geo);

    // Build response matching schema
    const data = {
      ip: clientIp,
      ipv6: ipv6,
      timezone: geo?.timezone || '',
      utc_offset: getUtcOffset(geo?.timezone) || '',
      asn: asnInfo.asn,
      org: asnInfo.org
    };

    res.status(200).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

function getIPv6(req) {
  // Try to get IPv6 from various sources
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const ips = forwarded.split(',').map(ip => ip.trim());
    for (const ip of ips) {
      if (ip.includes(':')) {
        return ip;
      }
    }
  }

  const remoteAddress = req.socket.remoteAddress || '';
  if (remoteAddress.includes(':') && remoteAddress !== '::1') {
    return remoteAddress;
  }

  return '';
}

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

function getASNInfo(ip, geo) {
  // Use geoip-lite's built-in ASN data if available
  if (geo && geo.asn) {
    return {
      asn: geo.asn.asn || '',
      org: geo.asn.org || ''
    };
  }

  // Fallback: return empty if not available
  return {
    asn: '',
    org: ''
  };
}
