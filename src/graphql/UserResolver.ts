import 'reflect-metadata';
import { Mutation, Query, Resolver, Arg, ObjectType, Field, Ctx, UseMiddleware, Int } from 'type-graphql';
import { User } from '../entity/User';
import { compare, hash } from 'bcryptjs';
import { IMyContext } from '../MyContext';
import { createAccessToken, createRefreshToken } from '../auth';
import { isAuth } from '../Middleware/isAuth';
import { sendRefreshToken } from '../sendRefreshToken';
// import { getConnection } from 'typeorm';
import { AppDataSource } from '../data-source';
import { verify } from 'jsonwebtoken';

@ObjectType()
class LoginResponse {
  @Field()
  accessToken: string;
  @Field(() => User)
  user: User;
}

@Resolver()
export class UserResolver {
  @Query(() => String)
  hello () {
    return 'Hello World!'
  }

  @Query(() => String)
  @UseMiddleware(isAuth)
  bye (
    @Ctx() { payload }: IMyContext
  ) {
    console.log(payload);
    const id = payload!.userId;
    return `Your user id is : ${id}!`
  }

  @Query(() => [User])
  async users () {
    return await User.find();
  }

  @Mutation(() => Boolean)
  async register (
    @Arg('email') email: string,
    @Arg('password') password: string
  ) {

    const hashedPassword = await hash(password, 12);

    try {
      await User.insert({
        email,
        password: hashedPassword
      })
    } catch (err) {
      console.log(err);
      return false;
    }

    return true;
  }

  @Mutation(() => LoginResponse)
  async login (
    @Arg('email') email: string,
    @Arg('password') password: string,
    @Ctx() { res }: IMyContext
  ): Promise<LoginResponse> {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      throw new Error('Could not find user');
    }

    const valid = await compare(password, user.password);

    if (!valid) {
      throw new Error('Bad password');
    }


    // Login successful
    // Set cookie with refresh token
    sendRefreshToken(res, createRefreshToken(user));

    // give them access token
    return {
      accessToken: createAccessToken(user),
      user
    };
  }

  // This is just a mutation for testing, normally we would never expose this
  @Mutation(() => Boolean)
  async revokeRefreshTokensForUser (
    @Arg('userId', () => Int) userId: number
  ) {
    // await getConnection().getRepository(User).increment({ id : userId }, "tokenVersion", 1)
    const updatedValue = await AppDataSource.getRepository(User).increment({ id: userId}, "tokenVersion", 1);
    console.log(updatedValue);

    return true;
  }

  @Query(() => User, { nullable: true })
  async me (
    @Ctx() context: IMyContext
  ) {
    const authorization = context.req.headers['authorization'];

    if (!authorization) {
      return null;
    }

    try {
      const token = authorization.split(' ')[1];
      const payload: any = verify(token, process.env.ACCESS_TOKEN_SECRET!);
      console.log(payload);
      return await User.findOne({ where : { id : payload.userId }});
    } catch (err) {
      console.log(err);
      return null;
    }
  }

  @Mutation(() => Boolean)
  async logout (
    @Ctx() { res }: IMyContext
  ) {
    sendRefreshToken(res, '');

    return true;
  }
}

