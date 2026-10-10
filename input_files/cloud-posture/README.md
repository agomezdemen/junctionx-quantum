# Cloud posture

Exports sinteticos (JSON) no formato das respetivas APIs AWS, para pratica
de auditoria de postura cloud: inventario de chaves KMS e configuracao de
listeners de load balancers. Nao correspondem a uma conta real — IDs de
conta, ARNs e identificadores seguem os valores de exemplo documentados
pela AWS (conta `123456789012`, etc.).

```
cloud-posture/
  kms_key_inventory.json        aproxima kms:ListKeys + kms:DescribeKey
  load_balancer_listeners.json  aproxima elasticloadbalancing:DescribeLoadBalancers + DescribeListeners
  acm_certificates.json         aproxima acm:DescribeCertificate para os certificados usados nos listeners
```

Os campos seguem os nomes reais das APIs (`KeySpec`, `KeyUsage`, `Origin`,
`KeyRotationStatus`, `SslPolicy`, etc.); para interpretar os valores de
`SslPolicy`, consultar a tabela oficial da AWS de politicas de seguranca
para ELB.
