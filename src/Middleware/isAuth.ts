import { IMyContext } from "src/MyContext";
import { verify } from "jsonwebtoken";
import { MiddlewareFn } from "type-graphql";
import { log } from "console";


// auth header should look like bearer 123

export const isAuth: MiddlewareFn<IMyContext> = ({ context }, next) => {
  const authorization =  context.req.headers['authorization'];

  if (!authorization) {
    throw new Error('not authenticated');
  }

  try {
    const token = authorization?.split(' ')[1];
    const payload = verify(token, process.env.ACCESS_TOKEN_SECRET!);
    context.payload = payload as { userId: string };
  } catch (error) {
    log(error);
    throw new Error('not authenticated');
  }

  return next();
};