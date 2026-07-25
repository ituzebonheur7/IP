const https = require('https');

module.exports = async (req, res) => {
  try {
    // Get client IP from request
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() ||
                     req.headers['x-real-ip'] ||
                     req.socket.remoteAddress ||
                     '127.0.0.1';

    // Query ipapi.co for geolocation data
    const response = await queryIpApi(clientIp);
    
    // Map response to schema
    const data = {
      ip: response.ip || clientIp,
      ipv6: response.ipv6 || '',
      postal: response.postal || '',
      timezone: response.timezone || '',
      utc_offset: response.utc_offset || '',
      languages: response.languages || '',
      asn: response.asn || '',
      org: response.org || ''
    };

    res.status(200).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

function queryIpApi(ip) {
  return new Promise((resolve, reject) => {
    const url = `https://ipapi.co/${ip}/json/`;
    
    https.get(url, (response) => {
      let data = '';
      response.on('data', chunk => data += chunk);
      response.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error('Failed to parse IP API response'));
        }
      });
    }).on('error', reject);
  });
}
