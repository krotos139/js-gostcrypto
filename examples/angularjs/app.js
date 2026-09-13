import angular from "angular";
import { registerGostCryptoModule } from "@gostcrypto/angularjs";
import { extractSubjectPublicKeyInfo, OID, parseSubjectPublicKeyInfo } from "@gostcrypto/asn1";
import { parseSignedData } from "@gostcrypto/cms";
import { createCryptoProBrowserProvider } from "@gostcrypto/providers";

function algorithmFor(certificate) {
  const { algorithmOid } = parseSubjectPublicKeyInfo(extractSubjectPublicKeyInfo(certificate.der));
  if (algorithmOid === OID.publicKey256) return "gost3410-2012-256";
  if (algorithmOid === OID.publicKey512) return "gost3410-2012-512";
  throw new Error(`Unsupported certificate algorithm: ${algorithmOid}`);
}

registerGostCryptoModule(angular, createCryptoProBrowserProvider());

angular.module("example", ["gostcrypto"]).controller("SignerController", ["$scope", "gostCrypto", function SignerController($scope, gostCrypto) {
  const vm = this;
  vm.text = "gostcrypto-js AngularJS example";
  vm.certificates = [];
  vm.status = "Reading certificates…";

  gostCrypto.listCertificates().then((certificates) => {
    vm.certificates = certificates.flatMap((certificate) => {
      if (!certificate.hasPrivateKey) return [];
      try { return [{ certificate, algorithm: algorithmFor(certificate) }]; }
      catch { return []; }
    });
    vm.selected = vm.certificates[0];
    vm.status = `${vm.certificates.length} supported certificate(s)`;
  }).catch((error) => { vm.status = error.message; }).finally(() => $scope.$applyAsync());

  vm.sign = async () => {
    vm.busy = true;
    vm.status = "Signing with CryptoPro…";
    try {
      const document = new TextEncoder().encode(vm.text);
      const signature = await gostCrypto.sign(vm.selected.certificate.id, document, {
        algorithm: vm.selected.algorithm,
        detached: true,
        checkCertificate: false,
      });
      parseSignedData(signature).verify(document);
      vm.status = `Signature created and verified (${signature.length} bytes).`;
    } catch (error) {
      vm.status = error instanceof Error ? error.message : String(error);
    } finally {
      vm.busy = false;
      $scope.$applyAsync();
    }
  };
}]);
