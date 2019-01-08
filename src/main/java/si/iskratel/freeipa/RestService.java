package si.iskratel.freeipa;

import org.apache.directory.kerberos.client.ChangePasswordResult;
import org.apache.directory.kerberos.client.ChangePasswordResultCode;
import org.apache.directory.kerberos.client.KdcConfig;
import org.apache.directory.kerberos.client.KdcConnection;
import org.apache.directory.server.kerberos.changepwd.exceptions.ChangePasswordException;
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.Set;

@RestController
@RequestMapping("/freeipa")
public class RestService {

    @RequestMapping(method = RequestMethod.GET)
    @ResponseBody
    public String findAll() {
        return "Status OK";
    }

    @RequestMapping(method = RequestMethod.POST)
    public ResponseEntity<?> changePwd(@RequestParam(value="username") String userPrincipal,
                                    @RequestParam(value="oldpasswd") String userPassword,
                                    @RequestParam(value="newpasswd") String newpassword) {
        KdcConfig config = KdcConfig.getDefaultConfig();
        config.setHostName("ldap.server.cz");
        config.setUseUdp(false);

        Set<EncryptionType> enct = new HashSet<EncryptionType>();
        enct.add(EncryptionType.AES256_CTS_HMAC_SHA1_96);
        config.setEncryptionTypes(enct);

        KdcConnection conn = new KdcConnection(config);
        ChangePasswordResult res = null;
        try {
            res = conn.changePassword(userPrincipal, userPassword, newpassword);
        } catch (ChangePasswordException e) {
            return new ResponseEntity<>(null, HttpStatus.UNPROCESSABLE_ENTITY);
        }
        if (res.getCode().compareTo(ChangePasswordResultCode.KRB5_KPASSWD_SUCCESS) == 0) {
            return new ResponseEntity<>(null, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null, HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

}
