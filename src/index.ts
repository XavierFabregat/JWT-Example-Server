import 'dotenv/config'
import { ApolloServer } from "apollo-server-express";
import express from "express"
import { buildSchema } from "type-graphql";
import { UserResolver } from "./graphql/UserResolver";
// import { createConnection } from "typeorm";
import 'reflect-metadata';
import { AppDataSource } from "./data-source";
import cookieParser from 'cookie-parser';
import { verify } from 'jsonwebtoken';
import { User } from './entity/User';
import { createAccessToken, createRefreshToken } from './auth';
import { sendRefreshToken } from './sendRefreshToken';
import cors from 'cors';


(async () => {
    const app = express();
    app.use(cors({
        credentials: true,
        origin: ["http://localhost:3000","https://studio.apollographql.com"]
    }))
    app.use(cookieParser());
    app.get('/', (_req, res) => {
        res.send('Hello World!');
    });

    app.post('/refresh_token', async (req, res) => {
        const token = req.cookies.jid;
        if (!token) {
            return res.send({ ok: false, accessToken: '' })
        }
        let payload: any = null;
        try {
            payload = verify(token, process.env.REFRESH_TOKEN_SECRET!);
        } catch (error) {
            console.log(error);
            return res.send({ ok: false, accessToken: '' })
        }

        // token is valid and we can send back an access token

        const user = await User.findOne({ where : { id: payload.userId as number }});

        if (!user) {
            return res.send({ ok: false, accessToken: '' })
        }

        if (user.tokenVersion !== payload.tokenVersion) {
            return res.send({ ok: false, accessToken: '' })
        }

        sendRefreshToken(res, createRefreshToken(user));

        return res.send({ ok: true, accessToken: createAccessToken(user) });
    });


    AppDataSource.initialize()

    const apolloServer = new ApolloServer({
        schema: await buildSchema({
            resolvers: [UserResolver]
        }),
        context: ({ req, res }) => ({ req, res })
    });

    await apolloServer.start();
    apolloServer.applyMiddleware({ app, cors: false });

    app.listen(4000, () => {
        console.log("Server started on http://localhost:4000");
    })
})();

