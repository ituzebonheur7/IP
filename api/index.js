const geoip = require('geoip-lite');

module.exports = async (req, res) => {
  try {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() ||
                     req.headers['x-real-ip'] ||
                     req.socket.remoteAddress ||
                     '127.0.0.1';

    const geo = geoip.lookup(clientIp);

    const ipv6 = getIPv6(req);

    const asnInfo = getASNInfo(clientIp, geo);

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
  if (geo && geo.asn) {
    return {
      asn: geo.asn.asn || '',
      org: geo.asn.org || ''
    };
  }

  return {
    asn: '',
    org: ''
  };
}
