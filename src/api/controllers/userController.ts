import bcrypt from "bcrypt";
import mongoose, { FilterQuery, HydratedDocument } from "mongoose";
import CustomError from "../../config/CustomError";
import asyncErrorHandler from "../helpers/asyncErrorHandler";
import StatusCode from "@static/types/backend/httpStatusCode";
import { MainWebsiteRole } from "@static/types/mainWebsiteRole";
import Permission from "@static/types/permissions";
import { user_to_response } from "../helpers/user_to_response";
import { IRole } from "../models/rolesModel";
import { IUser, PopulatedUser, User } from "../models/userModel";
import * as UserService from "../services/userService";
import { Blog } from "../models/blogModel";
import { assertHydratedUser, assertProtectedUser } from "../helpers/assertions";

/**
 * @description Retrieves all team members excluding those with the role MainWebsiteRole.DoNotDisplay.
 * @route GET /get-team
 * @param req - The HTTP request object.
 * @param res - The HTTP response object.
 * @returns A JSON response containing the fetched team members' details.
 * @returns status - Indicates the success status of the operation ('success').
 * @returns message - Describes the outcome of the operation ('Users fetched successfully').
 * @returns data - Contains an array of team member objects with filtered details.
 * @howItWorks
 * - Constructs a filter to exclude users with MainWebsiteRole.DoNotDisplay.
 * - Retrieves all users matching the filter using UserService.getAllUsers().
 * - Maps each user to include relevant details in the response.
 * - Sends a success response with the list of team members.
 */

export const getTeam = asyncErrorHandler(async (req, res) => {
  const filter: FilterQuery<HydratedDocument<IUser>> = {
    team_role: { $ne: MainWebsiteRole.DoNotDisplay },
  };

  const allUsers = await UserService.getAllUsers(filter);

  res.status(StatusCode.OK).json({
    status: "success",
    message: "Users fetched successfully",
    data: allUsers.map((user) => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { permission, is_superuser, ...user_resp } = user_to_response(user);
      return user_resp;
    }),
  });
});

/**
 * @description Retrieves all users.
 * @route GET /
 * @param req - The HTTP request object.
 * @param res - The HTTP response object.
 * @returns A JSON response containing the fetched users' details.
 * @returns status - Indicates the success status of the operation ('success').
 * @returns message - Describes the outcome of the operation ('Users fetched successfully').
 * @returns data - Contains an array of user objects with their details.
 * @howItWorks
 * - Retrieves all users using UserService.getAllUsers().
 * - Maps each user to include relevant details in the response.
 * - Sends a success response with the list of users.
 */

export const getAllUsers = asyncErrorHandler(async (req, res) => {
  //add logic here

  const allUsers = await UserService.getAllUsers({});

  res.status(StatusCode.OK).json({
    status: "success",
    message: "Users fetched successfully",
    data: allUsers.map((user) => {
      const user_resp = user_to_response(user);
      return user_resp;
    }),
  });
});

/**
 * @description Retrieves the current user details.
 * @route GET /current-user
 * @param req - The HTTP request object.
 * @param res - The HTTP response object.
 * @param next - The next middleware function in the stack.
 * @returns A JSON response containing the fetched user's details.
 * @returns status - Indicates the success status of the operation ('success').
 * @returns message - Describes the outcome of the operation ('User fetched successfully').
 * @returns data - Contains the details of the fetched user.
 * @howItWorks
 * - Asserts that the user is hydrated using `assertHydratedUser`.
 * - Retrieves the current user from `res.locals.user`.
 * - If no user is found, returns an unauthorized error.
 * - Converts the user object to a response format using `user_to_response`.
 * - Sends a success response with the user data.
 */

export const getCurrentUserController = asyncErrorHandler(
  async (req, res, next) => {
    assertHydratedUser(res);
    const user = res.locals.user;
    if (!user) {
      const error = new CustomError(
        "Unable to get current user",
        StatusCode.UNAUTHORIZED,
      );
      return next(error);
    }

    const user_resp = user_to_response(user);

    res.status(StatusCode.OK).json({
      status: "success",
      message: "User fetched successfully",
      data: user_resp,
    });
  },
);

/**
 * @description Retrieves user details by ID.
 * @route GET /get-user/:id
 * @param req - The HTTP request object.
 * @param res - The HTTP response object.
 * @param next - The next middleware function in the stack.
 * @returns A JSON response containing the fetched user's details.
 * @returns status - Indicates the success status of the operation ('success').
 * @returns message - Describes the outcome of the operation ('User fetched successfully').
 * @returns data - Contains the details of the fetched user.
 * @howItWorks
 * - Retrieves the user ID from `req.params.id`.
 * - Checks if the user exists using `UserService.checkUserExists`.
 * - If the user does not exist, returns an unauthorized error.
 * - Converts the user object to a response format using `user_to_response`.
 * - Sends a success response with the user data.
 */

export const getUserController = asyncErrorHandler(async (req, res, next) => {
  const user_id = new mongoose.Types.ObjectId(req.params.id);
  const user = await UserService.checkUserExists({ _id: user_id });
  if (!user) {
    const error = new CustomError(
      "Unable to get current user",
      StatusCode.UNAUTHORIZED,
    );
    return next(error);
  }

  const user_resp = user_to_response(user);

  res.status(StatusCode.OK).json({
    status: "success",
    message: "User fetched successfully",
    data: user_resp,
  });
});

/**
 * @description Adds user list to users database.
 * @route POST /post-add-users
 * @param req - The HTTP request object.
 * @param res - The HTTP response object.
 * @param next - The next middleware function in the stack.
 * @returns A JSON response containing the user database.
 * @returns status - Indicates the success status of the operation ('success').
 * @returns message - Describes the outcome of the operation ('User Data successfully inserted').
 * @returns data - Contains the data added to the users database.
 * @howItWorks
 * - Retrieves the array of users from `req.params.users`.
 * - Hashes all the password being added.
 * - adds all the data to users models
 */

export const postBulkUserController = asyncErrorHandler(
  async (req, res, next) => {
    const usersData = req.body.users;

    if (!Array.isArray(usersData)) {
      return res.status(400).json({ error: "user data must be an array" });
    }

    const hashedUsers = await Promise.all(
      usersData.map(async (user) => ({
        ...user,
        password: await bcrypt.hash(user.password, 10),
      })),
    );

    const userDocsInserted = await User.insertMany(hashedUsers);

    res.status(StatusCode.OK).json({
      message: "User Data successfully inserted",
      data: userDocsInserted,
    });
  },
);

/**
 * @description Updates user details including name, email, password, and bio.
 * @route PUT /update-user
 * @param req - The HTTP request object.
 * @param req.body.target_user_id - The ID of the user to update.
 * @param req.body.target_name - The updated name of the user.
 * @param req.body.target_email - The updated email of the user.
 * @param req.body.password - The updated password of the user.
 * @param req.body.target_bio - The updated biography of the user.
 * @param res - The HTTP response object.
 * @param next - The next middleware function in the stack.
 * @returns A JSON response indicating the success of the operation.
 * @returns status - Indicates the success status of the operation ('success').
 * @returns message - Describes the outcome of the operation ('User updated successfully').
 * @returns data - Contains the updated user details.
 * @returns data.user - Updated user object.
 * @howItWorks
 * - Asserts that the user making the request (`res.locals.user_id`) is protected.
 * - Retrieves `target_user_id` from `req.body` and checks if the user exists.
 * - If the user doesn't exist, throws a "Not Found" error.
 * - If the `target_user_id` doesn't match the current user's ID (`res.locals.user_id`), proceeds to the next middleware.
 * - Updates user properties (name, email, password, bio) if provided in the request body.
 * - Hashes the updated password using bcrypt.
 * - Saves the updated user details.
 * - Responds with a success message and updated user data.
 */

export const updateUserController = asyncErrorHandler(
  async (req, res, next) => {
    assertProtectedUser(res);
    const user_id = res.locals.user_id;
    const target_user_id = new mongoose.Types.ObjectId(
      req.body.target_user_id as string,
    );

    const user = await UserService.checkUserExists({ _id: target_user_id });
    if (!user) {
      const error = new CustomError(
        "Unable to get target user",
        StatusCode.NOT_FOUND,
      );
      return next(error);
    }

    res.locals.user = user;

    if (!target_user_id.equals(user_id)) {
      return next();
    }

    if (!user) {
      const error = new CustomError(
        "Unable to get current user",
        StatusCode.NOT_FOUND,
      );
      return next(error);
    }

    // Update user properties if provided in request body
    if (req.body.target_name) user.name = req.body.target_name;
    if (req.body.target_email) user.email = req.body.target_email;
    if (req.body.password) {
      const hashed_password: string = await bcrypt.hash(req.body.password, 10);
      user.password = hashed_password;
    }
    if (req.body.target_bio) user.bio = req.body.target_bio;

    await user.save();
    res.locals.user = user;
    if (!req.body.permission && !req.body.role_id) {
      const user_resp = user_to_response(user);

      return res.status(StatusCode.OK).json({
        status: "success",
        message: "User updated successfully",
        data: {
          user: user_resp,
        },
      });
    }
    return next();
  },
);

/**
 * @description Updates permissions, role, and team role for a user.
 * @route PUT /update-user
 * @param req - The HTTP request object.
 * @param req.body.permission - The updated permissions array.
 * @param req.body.role_id - The ID of the new role to assign to the user.
 * @param req.body.team_role - The team role for the user.
 * @param res - The HTTP response object.
 * @param next - The next middleware function in the stack.
 * @returns A JSON response indicating the success of the operation.
 * @returns status - Indicates the success status of the operation ('success').
 * @returns message - Describes the outcome of the operation ('User updated successfully').
 * @returns data - Contains the updated user details.
 * @returns data.user - Updated user object.
 * @howItWorks
 * - Asserts that the user object (`res.locals.user`) is hydrated.
 * - Retrieves `permission`, `role_id`, and `team_role` from `req.body`.
 * - If `user` is not found, throws an error.
 * - Updates the `role_id` of the user if provided in `req.body`.
 * - Computes changes in permissions (`removed_permissions` and `extra_permissions`).
 * - Updates `team_role` to default if not provided.
 * - Saves the updated user.
 * - Returns a success response with the updated user details.
 */

export const permsUpdateController = asyncErrorHandler(
  async (req, res, next) => {
    assertHydratedUser(res);
    let user: PopulatedUser = res.locals.user;
    const {
      permission,
      role_id,
    }: { permission: Permission[]; role_id: string } = req.body;

    if (!user) {
      const error = new CustomError(
        "Requested user not found",
        StatusCode.NOT_FOUND,
      );
      return next(error);
    }
    if (role_id) {
      const updated_user = await User.findByIdAndUpdate(
        user,
        {
          role_id: role_id,
        },
        { new: true },
      ).populate<{
        role_id: HydratedDocument<IRole>;
      }>("role_id");
      if (!updated_user) {
        const error = new CustomError(
          "Unable to update user",
          StatusCode.INTERNAL_SERVER_ERROR,
        );
        return next(error);
      }
      user = updated_user;
    }

    if (permission !== undefined || permission !== null) {
      const role_perms_taken_away = user.role_id.permissions.filter(
        (perm) => !permission.includes(perm),
      );
      const extra_perms_given = permission.filter(
        (perm) => !user.role_id.permissions.includes(perm),
      );
      user.removed_permissions = role_perms_taken_away;
      user.extra_permissions = extra_perms_given;
    }

    user.team_role =
      (req.body.team_role as MainWebsiteRole) || MainWebsiteRole.DoNotDisplay;

    await user.save();

    const user_resp = user_to_response(user);
    return res.status(StatusCode.OK).json({
      status: "success",
      message: "User updated successfully",
      data: {
        user: user_resp,
      },
    });
  },
);

/**
 * @description Deletes a user account.
 * @route DELETE /delete-user/:id
 * @param req - The HTTP request object.
 * @param req.params.id - The ID of the user to delete.
 * @param req.body.target_user_id - The ID of the user to be deleted.
 * @param res - The HTTP response object.
 * @param next - The next middleware function in the stack.
 * @returns A JSON response indicating the success of the operation.
 * @returns status - Indicates the success status of the operation ('success').
 * @returns message - Describes the outcome of the operation ('User deleted successfully').
 * @howItWorks
 * - Retrieves the `id` from `req.params`, which represents the ID of the user to delete.
 * - Retrieves `target_user_id` from `req.body`, which is used to find the user to delete.
 * - Checks if `target_user_id` is the default account owner (new_owner).
 *   - If yes, returns a forbidden error indicating the default account cannot be deleted.
 * - Checks if the user identified by `target_user_id` exists using `UserService.checkUserExists`.
 *   - If not found, returns a not found error indicating the user account could not be retrieved.
 * - Checks if `target_user_id` matches `user_id` (current user's ID).
 *   - If yes, returns a forbidden error indicating the user cannot delete their own account.
 * - Transfers ownership of all blogs associated with the user to `new_owner`.
 * - Deletes the user using `user.deleteOne()`.
 * - Logs the deletion and ownership transfer of blogs.
 * - Sends a success response indicating the user account was deleted successfully.
 */

export const deleteUserController = asyncErrorHandler(
  async (req, res, next) => {
    const { id } = req.params;
    const user_id = new mongoose.Types.ObjectId(id);
    const target_user_id = new mongoose.Types.ObjectId(
      req.body.target_user_id as string,
    );
    const new_owner = process.env.EMAIL_USER_OBJID 
      ? new mongoose.Types.ObjectId(process.env.EMAIL_USER_OBJID)
      : null;

    if (new_owner && target_user_id.equals(new_owner)) {
      const err = new CustomError(
        "You cannot delete the default account!",
        StatusCode.FORBIDDEN,
      );
      return next(err);
    }

    const user = await UserService.checkUserExists({ _id: target_user_id });

    if (!user) {
      const error = new CustomError(
        "Unable to get user account!",
        StatusCode.NOT_FOUND,
      );
      return next(error);
    }

    if (target_user_id.equals(user_id)) {
      const err = new CustomError(
        "You cannot delete your own account",
        StatusCode.FORBIDDEN,
      );
      return next(err);
    }

    const ownership = await Blog.updateMany(
      {
        user: user._id,
      },
      { user: new_owner },
    );

    console.log(
      "User",
      user,
      "deleted by",
      user_id,
      "upgraded ownership blogs result",
      ownership,
    );

    await user.deleteOne();

    res.status(StatusCode.OK).json({
      status: "success",
      message: "User deleted successfully",
    });
  },
);

/**
 * @description Deletes a user (superuser only)
 * @route DELETE /delete-user-superuser/:id
 * @param req - The HTTP request object.
 * @param res - The HTTP response object.
 * @returns A JSON response indicating the success of the user deletion.
 * @access Superuser only
 * @howItWorks
 * - Checks if the current user is a superuser
 * - Prevents deletion of the default account
 * - Prevents self-deletion
 * - Transfers blog ownership to default user
 * - Deletes the user account
 */
export const deleteUserBySuperuser = asyncErrorHandler(
  async (req, res, next) => {
    const { id } = req.params;
    const target_user_id = new mongoose.Types.ObjectId(id);
    const current_user_id = new mongoose.Types.ObjectId(res.locals.user_id);
    
    const currentUser = await UserService.checkUserExists({ _id: current_user_id });
    if (!currentUser || currentUser.role_id?._id?.toString() !== process.env.SUPERUSER_ROLE_ID) {
      const err = new CustomError(
        "Only superusers can delete users",
        StatusCode.FORBIDDEN,
      );
      return next(err);
    }

    if (target_user_id.equals(current_user_id)) {
      const err = new CustomError(
        "You cannot delete your own account",
        StatusCode.FORBIDDEN,
      );
      return next(err);
    }

    const targetUser = await UserService.checkUserExists({ _id: target_user_id });
    if (!targetUser) {
      const error = new CustomError(
        "User not found",
        StatusCode.NOT_FOUND,
      );
      return next(error);
    }

    const new_owner = process.env.EMAIL_USER_OBJID 
      ? new mongoose.Types.ObjectId(process.env.EMAIL_USER_OBJID)
      : null;
    
    if (new_owner) {
      await Blog.updateMany(
        { user: target_user_id },
        { user: new_owner }
      );
    }

    await targetUser.deleteOne();

    res.status(StatusCode.OK).json({
      status: "success",
      message: "User deleted successfully",
    });
  },
);
