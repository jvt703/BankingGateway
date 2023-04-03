package n1t.dev.APIGateway.filter;

import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class JWTFilter extends AbstractGatewayFilterFactory<JWTFilter.Config> {


    @Autowired
    private JWTService jwtService;

    public JWTFilter(){ super(Config.class);}

    public static class Config{

    };

    @Override

    public GatewayFilter apply(Config config){
        return ((exchange, chain) -> {

            final String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
            final String jwt;

            if (authHeader == null || !authHeader.startsWith("Bearer ")){
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return chain.filter(exchange);
            }

            jwt = authHeader.substring(7);
            try {
                jwtService.extractUsername(jwt);
                return chain.filter(exchange);
            }catch (JwtException e){
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();

            }

        });

    }
}
