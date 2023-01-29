import type {CtxOrReq} from "next-auth/client/_utils";
import {getCsrfToken, signIn, useSession} from "next-auth/react";
import {api} from "../utils/api";
import {useRouter} from "next/router";
import {z} from "zod";
import type {FieldValues} from "react-hook-form";
import { useForm} from "react-hook-form";
import {zodResolver} from "@hookform/resolvers/zod";
import {useEffect} from "react";

const registerSchema = z.object({
    email: z.string().email({message: 'Please enter a valid email address'}),
    password: z.string().min(6, {message: 'Password must be at least 6 characters'}),
    passwordConfirm: z.string().min(6, {message: 'Password must be at least 6 characters'}),
    name: z.string().min(2, {message: 'Name must be at least 2 characters'}),
}).refine((data) => data.password === data.passwordConfirm, {
    message: 'Passwords do not match', path: ['passwordConfirm']
});
export default function Register({csrfToken}: { csrfToken: string }) {
    // use create user mutation
    const session = useSession();
    const createUserMutation = api.user.register.useMutation();
    const router = useRouter();
    const {register, handleSubmit, formState: {errors}, setError} = useForm({
        resolver: zodResolver(registerSchema),
    });
    useEffect(() => {
        if(session && session.data?.user) {
            void router.push('/');
        }
    }, [session, router]);
    const submitHandler = async (data: FieldValues) => {
        createUserMutation.mutate({
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            email: data.email,
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            password: data.password,
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            name: data.name,
        } );
        // // sign in user
        const status = await signIn('credentials', {
            email: data.email,
            password: data.password,
            redirect: false,
            callbackUrl: '/',
        });
        if(status && !status.ok && status.error) {
            setError('email', {type: 'manual', message: status.error});
        }
        if(status && status.ok && status.url) {
            await router.push(status.url);
        }
    }
    return (
        <>
            <div className="flex min-h-full flex-col justify-center py-12 sm:px-6 lg:px-8">
                <div className="sm:mx-auto sm:w-full sm:max-w-md">
                    <h2 className="mt-6 text-center text-3xl font-bold tracking-tight text-gray-900">
                        Create a new account
                    </h2>
                </div>

                <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
                    <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
                        <form className="space-y-6" onSubmit={handleSubmit(submitHandler)}>
                            <input name="csrfToken" type="hidden" defaultValue={csrfToken}/>
                            <div>
                                <label htmlFor="name" className="block text-sm font-medium text-gray-700">
                                  Name
                                </label>
                                <div className="mt-1">
                                    <input
                                        className={`block w-full appearance-none rounded-md border ${errors.name ? 'border-rose-400': 'border-gray-300'} px-3 py-2 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm`}
                                        {...register('name')}
                                    />
                                </div>
                                {
                                    errors.name && <p className="mt-2 text-sm text-rose-600">Name Error</p>
                                }
                            </div>
                            <div>
                                <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                                    Email address
                                </label>
                                <div className="mt-1">
                                    <input
                                        className={`block w-full appearance-none rounded-md border ${errors.email ? 'border-rose-400': 'border-gray-300'} px-3 py-2 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm`}
                                        {...register('email')}
                                    />
                                </div>
                                {
                                    errors.email && <p className="mt-2 text-sm text-rose-600">email error</p>
                                }
                            </div>

                            <div>
                                <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                                    Password
                                </label>
                                <div className="mt-1">
                                    <input
                                        type="password"
                                        className={`block w-full appearance-none rounded-md border ${errors.password ? 'border-rose-400': 'border-gray-300'} px-3 py-2 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm`}
                                        {...register('password')}
                                    />
                                </div>
                                {
                                    errors.password && <p className="mt-2 text-sm text-rose-600">password error</p>
                                }
                            </div>

                            <div>
                                <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700">
                                    Confirm Password
                                </label>
                                <div className="mt-1">
                                    <input
                                        type="password"
                                        className={`block w-full appearance-none rounded-md border ${errors.passwordConfirm ? 'border-rose-400': 'border-gray-300'} px-3 py-2 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm`}
                                        {...register('passwordConfirm')}
                                    />
                                </div>
                                {
                                    errors.passwordConfirm && <p className="mt-2 text-sm text-rose-600">Password Confirm error</p>
                                }
                            </div>
                            {createUserMutation.isError && <p className="mt-2 text-sm text-rose-600">{createUserMutation.error.message}</p>}
                            <div>
                                <button
                                    disabled={createUserMutation.isLoading}
                                    type="submit"
                                    className="flex w-full justify-center rounded-md border border-transparent bg-indigo-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
                                >
                                    Sign in
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </>
    )
}

export async function getServerSideProps(context: CtxOrReq) {
    const csrfToken = await getCsrfToken(context)
    return {
        props: {csrfToken},
    }
}