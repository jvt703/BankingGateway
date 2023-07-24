package n1t.dev.APIGateway.filter;

import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class JWTFilter extends AbstractGatewayFilterFactory<JWTFilter.Config> {


    @Autowired
    private JWTService jwtService;

    public JWTFilter(){ super(Config.class);}

    public static class Config{

    };

    @Override
    //get id and role from request
    public GatewayFilter apply(Config config){
        return ((exchange, chain) -> {

            final String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
            final String jwt;

            if (authHeader == null || !authHeader.startsWith("Bearer ")){
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return chain.filter(exchange);
            }



            Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
            URI uri = exchange.getRequest().getURI();
            String path = uri.getPath();

            String id = null;
            Pattern pattern = Pattern.compile("/users/(?<id>\\d+)");
            Matcher matcher = pattern.matcher(path);
            if (matcher.matches()) {
                id = matcher.group("id");
            }
            if (route == null) {
                exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                return exchange.getResponse().setComplete();
            }
            jwt = authHeader.substring(7);
            try {
                jwtService.isTokenValid(jwt);
                //extract role and id from JWT token wait also I need to sign role into the token now
//                exchange.getRequest().mutate().header("Role", role);
//                exchange.getRequest().mutate().header("Id", String.valueOf(id));
                return chain.filter(exchange);
            }catch (JwtException e){
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();

            }

        });

    }
}
