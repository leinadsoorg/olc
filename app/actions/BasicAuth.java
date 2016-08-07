package actions;

import models.User;
import play.libs.F;
import play.mvc.Action;
import play.mvc.Http;
import play.mvc.SimpleResult;
import org.apache.commons.codec.binary.Base64;
import java.util.*;

/**
 * A simple action to perform an HTTP basic authentication prior accessing
 * certain actions.
 *
 * @author <a href="mailto:alexander.hanschke@techdev.de">Alexander Hanschke</a>
 */
public class BasicAuth extends Action.Simple {

    private static final String ACCOUNT = "account";

    private static final String REALM = "Basic realm=\"techdev\"";
    private static final String AUTHORIZATION = "authorization";
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    private static final F.Promise<SimpleResult> UNAUTHORIZED = F.Promise.pure((SimpleResult) unauthorized());

    @Override
    public F.Promise<SimpleResult> call(Http.Context context) throws Throwable {
        Optional<String> header = Optional.ofNullable(context.request().getHeader(AUTHORIZATION));

        if (!header.isPresent()) {
            context.response().setHeader(WWW_AUTHENTICATE, REALM);
            return UNAUTHORIZED;
        }

        String auth = header.get().substring(6);

        byte[] decoded = Base64.decodeBase64(auth.getBytes());

        String[] credentials = new String(decoded, "UTF-8").split(":");

        if (credentials == null || credentials.length != 2) {
            return UNAUTHORIZED;
        }

        String username = credentials[0];
        String password = credentials[1];

        User account = User.authenticate(username, password);

        return (account == null) ? UNAUTHORIZED : delegate.call(context);
    }

    public static Optional<User> account() {
        return Optional.ofNullable((User) Http.Context.current().args.get(ACCOUNT));
    }
}