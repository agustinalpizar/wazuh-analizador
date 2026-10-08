// Evento FICTICIO con el formato habitual de una alerta de Wazuh.
// IP 203.0.113.45 está en un rango reservado para documentación (RFC 5737); nada de esto es real.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.WAZUH_EJEMPLO = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  return {
    timestamp: '2026-10-04T22:13:07.512+0000',
    rule: {
      level: 10,
      description: 'sshd: brute force trying to get access to the system. Authentication failed.',
      id: '5763',
      mitre: {
        id: ['T1110'],
        tactic: ['Credential Access'],
        technique: ['Brute Force']
      },
      firedtimes: 3,
      mail: false,
      groups: ['syslog', 'sshd', 'authentication_failures']
    },
    agent: { id: '001', name: 'srv-demo-01', ip: '10.0.0.15' },
    manager: { name: 'wazuh-manager-demo' },
    id: '1759615987.123456',
    full_log: 'Oct  4 22:13:06 srv-demo-01 sshd[2211]: Failed password for invalid user usuario_demo from 203.0.113.45 port 51514 ssh2',
    predecoder: { program_name: 'sshd', timestamp: 'Oct  4 22:13:06', hostname: 'srv-demo-01' },
    decoder: { name: 'sshd' },
    data: { srcip: '203.0.113.45', srcport: '51514', dstuser: 'usuario_demo' },
    location: '/var/log/auth.log'
  };
});
